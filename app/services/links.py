"""Public download links: create, list, revoke and resolve ``/s/{token}``.

A link is a random 256-bit token. Only its SHA-256 is stored, so a leaked database dump contains
no working links, and the URL is shown exactly once, when the link is created. Anybody who knows
the token can download the file until the link expires, is revoked, or its owner is disabled
(then it works again after reactivation). Every reason a link does not work gives the same
``NotFound``, so a visitor cannot tell an expired link from a revoked or a made-up one.

The token and the URL are never written to the audit log or to any other log.
"""

import re
import uuid
from datetime import timedelta

from sqlalchemy import ColumnElement, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.errors import LinkLimit, NotFound, ValidationFailed
from app.metrics import DOWNLOADS
from app.models import File, ShareLink, User, UserStatus
from app.permissions import CurrentUser, can_modify_file, can_revoke_link
from app.security import generate_refresh_token, hash_token
from app.services import audit
from app.services.audit import AuditAction, AuditContext
from app.services.files import download_content_type
from app.storage.base import BlobStore

# At most this many links of one file may be valid at the same time (section 8.1).
MAX_ACTIVE_LINKS = 10
# What ``generate_refresh_token`` produces: 32 random bytes as 43 URL-safe characters.
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


def _active() -> ColumnElement[bool]:
    """SQL condition: not revoked and not expired.

    The database clock (``now()``) is used everywhere a link is checked, so creating, counting
    and opening a link agree on what "expired" means.
    """
    return ShareLink.revoked_at.is_(None) & (ShareLink.expires_at > func.now())


async def create_link(
    session: AsyncSession,
    settings: Settings,
    user: CurrentUser,
    file_id: uuid.UUID,
    hours: int,
    ctx: AuditContext,
) -> tuple[ShareLink, str]:
    """Create a public link for a file (owner only) and return it with its plain token.

    The token is returned only here; the caller builds the URL and must not log or store it.

    Raises:
        ValidationFailed: ``hours`` is above ``PUBLIC_LINK_MAX_HOURS``.
        NotFound: the file does not exist or the user is not the owner.
        LinkLimit: the file already has 10 active links.

    Side effects: one ``share_links`` row (hash only) and an audit entry ``link.create``.
    """
    if hours > settings.public_link_max_hours:
        raise ValidationFailed(
            [
                {
                    "field": "expires_in_hours",
                    "message": f"Must be at most {settings.public_link_max_hours} hours.",
                }
            ]
        )
    token = generate_refresh_token()
    async with session.begin():
        # Locking the file serializes parallel creates for it, so two requests cannot both
        # count 9 active links and both add the 10th and 11th.
        file = await session.scalar(
            select(File)
            .where(File.id == file_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if file is None or not can_modify_file(user, file):
            raise NotFound
        active = await session.scalar(
            select(func.count())
            .select_from(ShareLink)
            .where(ShareLink.file_id == file_id, _active())
        )
        if (active or 0) >= MAX_ACTIVE_LINKS:
            raise LinkLimit
        link = ShareLink(
            file_id=file_id,
            token_hash=hash_token(token),
            created_by=user.id,
            # The database clock, like every check of a link (_active, resolve_public_link).
            expires_at=func.now() + timedelta(hours=hours),
        )
        session.add(link)
        await session.flush()
        await session.refresh(link)  # load created_at
        await audit.record(
            session,
            ctx,
            AuditAction.link_create,
            target_type="link",
            target_id=link.id,
            target_label=file.filename,
            details={"file_id": str(file_id), "expires_at": link.expires_at.isoformat()},
        )
    return link, token


async def list_links(
    session: AsyncSession, user: CurrentUser, file_id: uuid.UUID
) -> list[ShareLink]:
    """All links of a file, newest first, including expired and revoked ones (owner only).

    Raises:
        NotFound: the file does not exist or the user is not the owner.
    """
    async with session.begin():
        file = await session.get(File, file_id, populate_existing=True)
        if file is None or not can_modify_file(user, file):
            raise NotFound
        result = await session.scalars(
            select(ShareLink)
            .where(ShareLink.file_id == file_id)
            .order_by(ShareLink.created_at.desc(), ShareLink.id.desc())
            .execution_options(populate_existing=True)
        )
        return list(result)


async def revoke_link(
    session: AsyncSession, user: CurrentUser, link_id: int, ctx: AuditContext
) -> File:
    """Revoke a link (the file's owner or an admin) and return its file.

    Idempotent: revoking again changes nothing and keeps the first revocation time.

    Raises:
        NotFound: no such link, or the user is neither the owner nor an admin.

    Side effect: audit entry ``link.revoke`` only when the link was revoked now.
    """
    async with session.begin():
        row = (
            await session.execute(
                select(ShareLink, File)
                .join(File, File.id == ShareLink.file_id)
                .where(ShareLink.id == link_id)
            )
        ).first()
        if row is None or not can_revoke_link(user, row[1]):
            raise NotFound
        file = row[1]
        # The condition keeps the first revocation time if two requests race.
        revoked = await session.scalar(
            update(ShareLink)
            .where(ShareLink.id == link_id, ShareLink.revoked_at.is_(None))
            .values(revoked_at=func.now())
            .returning(ShareLink.id)
        )
        if revoked is not None:
            await audit.record(
                session,
                ctx,
                AuditAction.link_revoke,
                target_type="link",
                target_id=link_id,
                target_label=file.filename,
                details={"file_id": str(file.id)},
            )
        return file


async def resolve_public_link(
    session: AsyncSession, settings: Settings, store: BlobStore, token: str, ctx: AuditContext
) -> str:
    """Check a link token, count the download and return a fresh short-lived download URL.

    ``ctx`` is the anonymous audit context of the visitor. The URL is signed inside the
    transaction: if blob storage fails, the count and the audit entry are rolled back.

    Raises:
        NotFound: for every reason the link does not work (malformed, unknown, expired,
            revoked, owner not active, file gone). Always the same, so nothing leaks.
        StorageUnavailable: blob storage failed (the link itself is valid).

    Side effects: ``download_count`` + 1 and an audit entry ``link.download``.
    """
    # A malformed token cannot exist: refuse without touching the database.
    if not TOKEN_PATTERN.fullmatch(token):
        raise NotFound
    async with session.begin():
        # One statement checks everything and counts, so a revoke, an expiry or a disabled
        # owner cannot slip in between "is it valid?" and "count it". The owner must be active
        # (section 5); after reactivation the same link works again.
        usable_files = (
            select(File.id)
            .join(User, User.id == File.owner_id)
            .where(User.status == UserStatus.active)
        )
        hit = (
            await session.execute(
                update(ShareLink)
                .where(
                    ShareLink.token_hash == hash_token(token),
                    ShareLink.revoked_at.is_(None),
                    ShareLink.expires_at > func.now(),
                    ShareLink.file_id.in_(usable_files),
                )
                .values(download_count=ShareLink.download_count + 1)
                .returning(ShareLink.id, ShareLink.file_id)
            )
        ).first()
        if hit is None:
            raise NotFound
        link_id, file_id = hit
        file = await session.get(File, file_id, populate_existing=True)
        if file is None:  # deleted in the meantime; leaving the block rolls the count back
            raise NotFound
        url = await store.download_url(
            file.blob_name,
            filename=file.filename,
            content_type=download_content_type(file.content_type),
            ttl_seconds=settings.sas_url_ttl_seconds,
        )
        await audit.record(
            session,
            ctx,
            AuditAction.link_download,
            target_type="link",
            target_id=link_id,
            target_label=file.filename,
            details={"file_id": str(file_id)},
        )
    DOWNLOADS.labels("public_link").inc()
    return url
