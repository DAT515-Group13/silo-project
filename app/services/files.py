"""File service: upload, listing, metadata, rename, download and delete.

Every public function owns its transaction and writes its audit entry. Missing access is always
``NotFound`` (404), so a stranger cannot tell whether a file exists.

Uploads stream through the app to blob storage: the bytes are counted on the way, so a file
that is too large or does not fit into the quota is stopped early and no blob is created. The
database (quota, ``files`` row, audit entry) is only touched after the blob is stored, in one
short transaction; if that fails, the blob is deleted again. The rules for a file's content
type live here too: the browser's ``Content-Type`` can be wrong or malicious, so on upload we
look at the first bytes first, and on download types a browser would display or run (HTML, SVG,
XML, JavaScript) are replaced by ``application/octet-stream``, so the browser saves a shared
file instead of rendering it.
"""

import logging
import re
import uuid
from collections.abc import AsyncIterator
from typing import Literal

import anyio
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.errors import FileTooLarge, NotFound, QuotaExceeded, StorageUnavailable, ValidationFailed
from app.models import File, FileShare, Team, User
from app.permissions import (
    CurrentUser,
    can_delete_file,
    can_download_file,
    can_modify_file,
    can_share_with_team,
    can_view_file,
)
from app.schemas.files import sanitize_filename
from app.services import audit, teams, users
from app.services.audit import AuditAction, AuditContext, Outcome
from app.services.pagination import fetch_page
from app.services.teams import FileItem
from app.storage.base import BlobStore

logger = logging.getLogger("silo")

# First bytes of common formats. The client's Content-Type is never trusted on its own.
_SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"ID3", "audio/mpeg"),
]

_MP4_BRANDS = {b"isom", b"iso2", b"mp41", b"mp42", b"avc1"}
# Signatures that many formats share (.docx, .xlsx, .odt and .jar are all ZIP files): a clean
# type from the client is more precise there, so it wins.
_SHARED_SIGNATURES = {"application/zip"}

# A plain "type/subtype" without parameters.
_CONTENT_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
MAX_CONTENT_TYPE_LENGTH = 127

DEFAULT_CONTENT_TYPE = "application/octet-stream"

# Types a browser would render (and run scripts from) instead of saving.
_RISKY_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/xml",
    "application/xml",
    "text/javascript",
    "application/javascript",
}


def sniff_content_type(head: bytes) -> str | None:
    """Detect the type from the first bytes of a file, or None if unknown."""
    for prefix, content_type in _SIGNATURES:
        if head.startswith(prefix):
            return content_type
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    # "ftyp" is shared by MP4, HEIC, AVIF, M4A and MOV: only the plain MP4 brands are claimed.
    if head[4:8] == b"ftyp" and head[8:12] in _MP4_BRANDS:
        return "video/mp4"
    return None


def normalize_content_type(client_value: str | None) -> str | None:
    """Clean the type the client sent: lowercase, no parameters, valid shape; else None.

    The value is stored and later goes into a SAS URL parameter, so only a clean
    ``type/subtype`` is accepted.
    """
    if not client_value:
        return None
    value = client_value.split(";", 1)[0].strip().lower()
    if len(value) > MAX_CONTENT_TYPE_LENGTH or not _CONTENT_TYPE.fullmatch(value):
        return None
    return value


def choose_content_type(head: bytes, client_value: str | None) -> str:
    """Upload step 3: detected type, else the client's clean value, else octet-stream.

    For signatures shared by many formats (ZIP) the client's clean value is preferred, unless
    it is a type a browser would render: a ZIP file is never stored as ``text/html``.
    """
    sniffed = sniff_content_type(head)
    client = normalize_content_type(client_value)
    if sniffed in _SHARED_SIGNATURES and client and download_content_type(client) == client:
        return client
    return sniffed or client or DEFAULT_CONTENT_TYPE


def download_content_type(stored: str) -> str:
    """Type to send when downloading: risky types become octet-stream."""
    if stored in _RISKY_TYPES or stored.endswith("+xml"):
        return DEFAULT_CONTENT_TYPE
    return stored


# --- Upload --------------------------------------------------------------------------------------

Scope = Literal["mine", "shared"]
Sort = Literal["created_at", "-created_at", "filename", "-filename", "size_bytes", "-size_bytes"]

# The multipart envelope (boundaries, part headers) adds a little to Content-Length.
MULTIPART_MARGIN_BYTES = 64 * 1024
# How many bytes of a file are looked at to detect its type.
SNIFF_BYTES = 32


async def _with_head(chunks: AsyncIterator[bytes]) -> tuple[bytes, AsyncIterator[bytes]]:
    """Read the first few bytes of a stream and return them with a stream that still has them."""
    source = chunks.__aiter__()
    buffered: list[bytes] = []
    size = 0
    async for chunk in source:
        buffered.append(chunk)
        size += len(chunk)
        if size >= SNIFF_BYTES:
            break
    head = b"".join(buffered)

    async def whole() -> AsyncIterator[bytes]:
        if head:
            yield head
        async for chunk in source:
            yield chunk

    return head[:SNIFF_BYTES], whole()


async def _limited(
    chunks: AsyncIterator[bytes], *, max_size: int, remaining: int
) -> AsyncIterator[bytes]:
    """Pass chunks on while counting; stop as soon as the file is too large or over quota.

    Raising here aborts the blob upload before anything is committed (upload step 2). The size
    limit is checked first, so a file that breaks both limits is reported as too large.
    """
    total = 0
    async for chunk in chunks:
        total += len(chunk)
        if total > max_size:
            raise FileTooLarge
        if total > remaining:
            raise QuotaExceeded
        yield chunk


async def _delete_quietly(store: BlobStore, blob_name: str) -> None:
    """Delete a blob, logging instead of raising: the caller's own error must not be masked.

    A blob that could not be deleted stays behind as an orphan; orphan cleanup removes it later.
    """
    try:
        await store.delete(blob_name)
    except StorageUnavailable:
        logger.warning("Could not delete blob %s; it is left for orphan cleanup", blob_name)


async def _audit_denied(session: AsyncSession, ctx: AuditContext, filename: str, code: str) -> None:
    """Audit a refused upload in its own session, so the entry survives the rollback.

    A failure here is only logged: it must not replace the 413 the client should receive.
    """
    try:
        await audit.record_failure(
            session,
            ctx,
            AuditAction.file_upload,
            outcome=Outcome.denied,
            target_type="file",
            target_label=filename,
            details={"code": code},
        )
    except Exception:
        logger.exception("Could not write the audit entry of a denied upload")


async def upload(
    session: AsyncSession,
    settings: Settings,
    store: BlobStore,
    user: CurrentUser,
    ctx: AuditContext,
    *,
    filename: str,
    client_type: str | None,
    chunks: AsyncIterator[bytes],
    declared_size: int | None,
) -> FileItem:
    """Store an uploaded file: size hint, quota check, stream to blob storage, then database.

    The comments mark the five steps of the upload flow. ``declared_size`` is the request's
    Content-Length: only a hint, used to refuse obviously oversized uploads before reading them.

    Raises:
        ValidationFailed: the file name is empty after cleaning.
        FileTooLarge: over ``MAX_FILE_SIZE_BYTES`` (no blob is created).
        QuotaExceeded: does not fit into the user's remaining quota (no blob remains).
        StorageUnavailable: blob storage failed.

    Side effects: one blob, one ``files`` row, the user's ``used_bytes`` and an audit entry
    ``file.upload``; denied uploads (too large, over quota) get a ``denied`` audit entry.
    """
    try:
        clean_name = sanitize_filename(filename)
    except ValueError as exc:
        raise ValidationFailed([{"field": "file", "message": str(exc)}]) from None

    blob_name = uuid.uuid4().hex  # random, never derived from user input
    blob_stored = False
    try:
        # Step 1: Content-Length is a hint only, but a huge value is refused without reading.
        max_size = settings.max_file_size_bytes
        if declared_size is not None and declared_size > max_size + MULTIPART_MARGIN_BYTES:
            raise FileTooLarge

        # Step 2: how much room is left. A stale value is fine; step 4 is the binding check.
        status = await users.get_quota_status(session, settings, user.id)
        if not status.can_upload:
            raise QuotaExceeded

        # Step 3: detect the type from the first bytes; stream the rest to blob storage.
        head, stream = await _with_head(chunks)
        content_type = choose_content_type(head, client_type)
        size = await store.upload_stream(
            blob_name,
            _limited(stream, max_size=max_size, remaining=status.remaining),
            content_type=content_type,
        )
        blob_stored = True

        # Step 4: one short transaction. The atomic quota UPDATE is the real check: a parallel
        # upload may have used the space meanwhile.
        async with session.begin():
            await users.reserve_quota(session, settings, user.id, size)
            file = File(
                owner_id=user.id,
                filename=clean_name,
                content_type=content_type,
                size_bytes=size,
                blob_name=blob_name,
            )
            session.add(file)
            await session.flush()
            await session.refresh(file)  # load created_at
            await audit.record(
                session,
                ctx,
                AuditAction.file_upload,
                target_type="file",
                target_id=str(file.id),
                target_label=clean_name,
                details={"size_bytes": size, "content_type": content_type},
            )
        return FileItem(file=file, owner_username=user.username)
    except BaseException as exc:
        # Step 5: anything after the blob was stored removes it again; used_bytes did not change
        # because the transaction above rolled back. BaseException also covers a cancelled
        # request, and the shield lets the cleanup finish even then.
        with anyio.CancelScope(shield=True):
            if blob_stored:
                await _delete_quietly(store, blob_name)
            if isinstance(exc, FileTooLarge | QuotaExceeded):
                await _audit_denied(session, ctx, clean_name, exc.code)
        raise


# --- Reading -------------------------------------------------------------------------------------

_SORTS = {
    "created_at": File.created_at.asc(),
    "-created_at": File.created_at.desc(),
    "filename": File.filename.asc(),
    "-filename": File.filename.desc(),
    "size_bytes": File.size_bytes.asc(),
    "-size_bytes": File.size_bytes.desc(),
}


async def _load(session: AsyncSession, file_id: uuid.UUID, *, lock: bool = False) -> FileItem:
    """Load a file with its owner's name, without any permission check. Caller's transaction.

    ``lock`` takes ``FOR UPDATE`` on the file row. ``populate_existing`` because the request's
    session keeps objects across transactions and the row may have changed meanwhile.
    """
    statement = (
        select(File, User.username)
        .join(User, User.id == File.owner_id)
        .where(File.id == file_id)
        .execution_options(populate_existing=True)
    )
    if lock:
        statement = statement.with_for_update(of=File)
    row = (await session.execute(statement)).first()
    if row is None:
        raise NotFound
    return FileItem(file=row[0], owner_username=row[1])


async def _load_visible(session: AsyncSession, user: CurrentUser, file_id: uuid.UUID) -> FileItem:
    """Load a file the user may see (owner or team member), else ``NotFound``."""
    item = await _load(session, file_id)
    shared = await teams.is_shared_with_user(session, file_id, user.id)
    # Same 404 as "does not exist", so IDs cannot be probed.
    if not can_view_file(user, item.file, shared_with_user=shared):
        raise NotFound
    return item


async def list_files(
    session: AsyncSession, user: CurrentUser, *, scope: Scope, sort: Sort, page: int, size: int
) -> tuple[list[FileItem], int]:
    """List the user's own files (``mine``) or files shared with their teams (``shared``)."""
    statement = select(File, User.username).join(User, User.id == File.owner_id)
    if scope == "mine":
        statement = statement.where(File.owner_id == user.id)
    else:
        statement = statement.where(
            File.id.in_(teams.shared_file_ids_for_user(user.id)), File.owner_id != user.id
        )
    # File.id as the last key keeps pages stable when the sort column has duplicates.
    statement = statement.order_by(_SORTS[sort], File.id)
    async with session.begin():
        rows, total = await fetch_page(session, statement, page=page, size=size)
    return [FileItem(file=row[0], owner_username=row[1]) for row in rows], total


async def get_file(session: AsyncSession, user: CurrentUser, file_id: uuid.UUID) -> FileItem:
    """Metadata of a file the user may see.

    Raises:
        NotFound: the file does not exist or the user may not see it.
    """
    async with session.begin():
        return await _load_visible(session, user, file_id)


# --- Changing ------------------------------------------------------------------------------------


async def rename_file(
    session: AsyncSession,
    user: CurrentUser,
    file_id: uuid.UUID,
    new_name: str,
    ctx: AuditContext,
) -> FileItem:
    """Rename a file (owner only). ``new_name`` is already cleaned by the schema.

    Raises:
        NotFound: the file does not exist or the user is not the owner.
    """
    async with session.begin():
        item = await _load(session, file_id, lock=True)
        if not can_modify_file(user, item.file):
            raise NotFound
        old_name = item.file.filename
        item.file.filename = new_name
        await audit.record(
            session,
            ctx,
            AuditAction.file_rename,
            target_type="file",
            target_id=str(file_id),
            target_label=new_name,
            details={"from": old_name, "to": new_name},
        )
    return item


async def download_url(
    session: AsyncSession,
    settings: Settings,
    store: BlobStore,
    user: CurrentUser,
    file_id: uuid.UUID,
    ctx: AuditContext,
) -> str:
    """Authorize a download and return a short-lived SAS URL (owner or team member, never admin).

    The URL is a secret: callers must not log or store it. The bytes never pass through the app.

    Raises:
        NotFound: no such file or no access.
        StorageUnavailable: blob storage failed.
    """
    async with session.begin():
        item = await _load(session, file_id)
        shared = await teams.is_shared_with_user(session, file_id, user.id)
        if not can_download_file(user, item.file, shared_with_user=shared):
            raise NotFound
        # Signed before the audit entry: if storage fails, no download is recorded.
        url = await store.download_url(
            item.file.blob_name,
            filename=item.file.filename,
            content_type=download_content_type(item.file.content_type),
            ttl_seconds=settings.sas_url_ttl_seconds,
        )
        await audit.record(
            session,
            ctx,
            AuditAction.file_download,
            target_type="file",
            target_id=str(file_id),
            target_label=item.file.filename,
        )
    return url


async def delete_file(
    session: AsyncSession,
    store: BlobStore,
    user: CurrentUser,
    file_id: uuid.UUID,
    ctx: AuditContext,
) -> None:
    """Delete a file (owner or admin) and give its bytes back to the owner's quota.

    The row, the quota and the audit entry change in one transaction; the blob is deleted after
    it. If that fails the blob stays as an orphan until orphan cleanup (the user's file is gone
    either way).

    Raises:
        NotFound: no such file, or the user is neither owner nor admin.
    """
    async with session.begin():
        item = await _load(session, file_id, lock=True)
        file = item.file
        if not can_delete_file(user, file):
            raise NotFound
        blob_name = file.blob_name
        await session.delete(file)
        # The owner's quota, also when an admin deletes someone else's file.
        await users.release_quota(session, file.owner_id, file.size_bytes)
        await audit.record(
            session,
            ctx,
            AuditAction.file_delete,
            target_type="file",
            target_id=str(file_id),
            target_label=file.filename,
            details={"size_bytes": file.size_bytes, "owner_id": file.owner_id},
        )
    await _delete_quietly(store, blob_name)


# --- Sharing with teams --------------------------------------------------------------------------


async def list_file_teams(
    session: AsyncSession, user: CurrentUser, file_id: uuid.UUID
) -> list[Team]:
    """Teams a file is shared with, by name (owner only).

    Raises:
        NotFound: the file does not exist or the user is not the owner.
    """
    async with session.begin():
        item = await _load(session, file_id)
        if not can_modify_file(user, item.file):
            raise NotFound
        statement = (
            select(Team)
            .join(FileShare, FileShare.team_id == Team.id)
            .where(FileShare.file_id == file_id)
            .order_by(Team.name, Team.id)
        )
        return list((await session.scalars(statement)).all())


async def share_with_team(
    session: AsyncSession,
    user: CurrentUser,
    file_id: uuid.UUID,
    team_id: int,
    ctx: AuditContext,
) -> None:
    """Share a file with a team the owner belongs to. Idempotent.

    Raises:
        NotFound: the file is not the user's, or the team does not exist or the user is not a
            member (the same answer, so team IDs cannot be probed).

    Side effect: audit entry ``file.share`` only when a new share was created.
    """
    async with session.begin():
        item = await _load(session, file_id, lock=True)
        if not can_modify_file(user, item.file):
            raise NotFound
        # Lock the team row (shared lock) so a parallel team delete cannot leave a share
        # pointing at a vanished team (that would be a foreign key error, a 500).
        team_name = await session.scalar(
            select(Team.name).where(Team.id == team_id).with_for_update(read=True)
        )
        if team_name is None:
            raise NotFound
        member = await teams.is_team_member(session, team_id, user.id)
        if not can_share_with_team(user, item.file, user_is_member=member):
            raise NotFound
        # ON CONFLICT DO NOTHING: sharing twice is not an error and writes no second audit row.
        added = await session.scalar(
            pg_insert(FileShare)
            .values(file_id=file_id, team_id=team_id)
            .on_conflict_do_nothing()
            .returning(FileShare.file_id)
        )
        if added is not None:
            await audit.record(
                session,
                ctx,
                AuditAction.file_share,
                target_type="file",
                target_id=str(file_id),
                target_label=item.file.filename,
                details={"team_id": team_id, "team_name": team_name},
            )


async def unshare_from_team(
    session: AsyncSession,
    user: CurrentUser,
    file_id: uuid.UUID,
    team_id: int,
    ctx: AuditContext,
) -> None:
    """Stop sharing a file with a team (owner only). Idempotent: no share is not an error.

    Raises:
        NotFound: the file does not exist or the user is not the owner.

    Side effect: audit entry ``file.unshare`` only when a share was removed.
    """
    async with session.begin():
        item = await _load(session, file_id, lock=True)
        if not can_modify_file(user, item.file):
            raise NotFound
        removed = await session.scalar(
            delete(FileShare)
            .where(FileShare.file_id == file_id, FileShare.team_id == team_id)
            .returning(FileShare.file_id)
        )
        if removed is not None:
            await audit.record(
                session,
                ctx,
                AuditAction.file_unshare,
                target_type="file",
                target_id=str(file_id),
                target_label=item.file.filename,
                details={"team_id": team_id},
            )
