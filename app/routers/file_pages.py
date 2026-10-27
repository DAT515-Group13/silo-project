"""File pages and their form actions.

Each form action calls the same service function as its JSON counterpart in
``routers/api/files.py``, with the same permissions, rate limits and audit entries. Domain
errors that are not handled here (404 for no access) become the HTML error page through the
exception handler.

The upload form is special. ``CsrfChecked`` reads the whole form, and Starlette would then write
large files to the local disk. So the upload route checks the Origin first, then reads the
hidden ``csrf_token`` field as the *first* part of the stream (the form puts it before the file
input, and browsers send fields in page order), verifies it, and only then streams the file part
to blob storage.
"""

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import ValidationError

from app.config import Settings
from app.errors import (
    CsrfFailed,
    FileTooLarge,
    LinkLimit,
    QuotaExceeded,
    RateLimited,
    ValidationFailed,
)
from app.middleware import safe_next
from app.permissions import CurrentUser, can_delete_file, can_modify_file
from app.ratelimit import limit, upload_slot
from app.routers.common import (
    MAX_ID,
    CsrfChecked,
    DbSession,
    IntId,
    PageAuditCtx,
    PageNumber,
    PageUser,
    SettingsDep,
    Store,
    check_csrf_value,
    declared_size,
    file_out,
    link_url,
    render_page,
    see_other,
    validation_messages,
    verify_origin,
)
from app.routers.multipart import MultipartReader, drain_refused_upload
from app.schemas.files import NO_FILE_MESSAGE, FileRenameIn
from app.schemas.links import LinkCreateIn
from app.services import files, links, teams, users

router = APIRouter(include_in_schema=False)

FILES_PER_PAGE = 20
# The CSRF token is about 70 characters; anything much longer in the first part is not one.
MAX_CSRF_FIELD_BYTES = 256

SORT_CHOICES = [
    ("-created_at", "Newest"),
    ("created_at", "Oldest"),
    ("filename", "Name A-Z"),
    ("-filename", "Name Z-A"),
    ("-size_bytes", "Largest"),
    ("size_bytes", "Smallest"),
]


# --- File list and upload ------------------------------------------------------------------------


async def _files_page(
    request: Request,
    session: DbSession,
    settings: Settings,
    user: CurrentUser,
    *,
    tab: files.Scope = "mine",
    sort: files.Sort = "-created_at",
    page: int = 1,
    notice: str | None = None,
    errors: list[str] | None = None,
    status_code: int = 200,
) -> Response:
    """Render ``files.html``: quota bar, upload form, and one tab of the user's files."""
    status = await users.get_quota_status(session, settings, user.id)
    items, total = await files.list_files(
        session, user, scope=tab, sort=sort, page=page, size=FILES_PER_PAGE
    )
    return render_page(
        request,
        settings,
        user,
        "files.html",
        {
            "files": [file_out(item, user.id) for item in items],
            "tab": tab,
            "sort": sort,
            "sort_choices": SORT_CHOICES,
            "page": page,
            "pages": max(1, -(-total // FILES_PER_PAGE)),
            "total": total,
            "used_bytes": status.used_bytes,
            "quota_bytes": status.quota_bytes,
            "max_file_bytes": settings.max_file_size_bytes,
            "notice": notice,
            "errors": errors or [],
        },
        status_code=status_code,
    )


@router.get("/files")
@limit("read")
async def files_page(
    request: Request,
    user: PageUser,
    session: DbSession,
    settings: SettingsDep,
    tab: files.Scope = "mine",
    sort: files.Sort = "-created_at",
    page: PageNumber = 1,
    uploaded: bool = False,
) -> Response:
    """The user's files with a quota bar and the upload form; a second tab shows shared files."""
    notice = "File uploaded." if uploaded else None
    return await _files_page(
        request, session, settings, user, tab=tab, sort=sort, page=page, notice=notice
    )


def _messages(error: ValidationFailed) -> list[str]:
    """The messages of a business validation error, for the page's error box."""
    return [item["message"] for item in error.errors]


async def _read_small(chunks: AsyncIterator[bytes], limit_bytes: int) -> str:
    """Read a short form field completely; a longer one is not a CSRF token.

    Raises:
        CsrfFailed: if the field is longer than ``limit_bytes``.
    """
    data = b""
    async for chunk in chunks:
        data += chunk
        if len(data) > limit_bytes:
            raise CsrfFailed
    return data.decode("utf-8", errors="replace")


@router.post("/files/upload", dependencies=[Depends(verify_origin)])
@limit("upload")
async def upload_submit(
    request: Request,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    settings: SettingsDep,
    store: Store,
) -> Response:
    """Upload one file from the form on ``/files``.

    Not protected by ``CsrfChecked`` (see the module docstring): the token is the first part of
    the body and is verified before the file part is read. A refused file shows the list again
    with a message.

    Raises:
        CsrfFailed: Origin, token or part order is wrong (403).
    """
    body = request.stream()
    try:
        async with upload_slot(user.id):
            reader = MultipartReader(request.headers.get("content-type", ""), body, max_parts=2)
            # Part 1: the CSRF token. Nothing of the file has been read when this is checked.
            first = await reader.next_part()
            if first is None or first.name != "csrf_token" or first.filename is not None:
                raise CsrfFailed
            token = await _read_small(reader.iter_data(), MAX_CSRF_FIELD_BYTES)
            check_csrf_value(request, settings, user, token)

            # Part 2: the file, streamed on to blob storage.
            part = await reader.next_part()
            if part is None or part.name != "file" or part.filename is None:
                raise ValidationFailed([{"field": "file", "message": NO_FILE_MESSAGE}])
            await files.upload(
                session,
                settings,
                store,
                user,
                ctx,
                filename=part.filename,
                client_type=part.content_type,
                chunks=reader.iter_data(),
                declared_size=declared_size(request),
            )
    except (FileTooLarge, QuotaExceeded, ValidationFailed, RateLimited) as exc:
        # Let the browser finish sending, or the proxy may turn this answer into a 502.
        await drain_refused_upload(
            body, declared_size=declared_size(request), max_file_bytes=settings.max_file_size_bytes
        )
        if isinstance(exc, RateLimited):
            raise  # the 429 error page
        errors = _messages(exc) if isinstance(exc, ValidationFailed) else [exc.detail]
        return await _files_page(
            request, session, settings, user, errors=errors, status_code=exc.status_code
        )
    return see_other("/files?uploaded=1")


# --- One file ------------------------------------------------------------------------------------


async def _file_page(
    request: Request,
    session: DbSession,
    settings: Settings,
    user: CurrentUser,
    file_id: uuid.UUID,
    *,
    notice: str | None = None,
    errors: list[str] | None = None,
    new_link_url: str | None = None,
    status_code: int = 200,
) -> Response:
    """Render ``file_detail.html``: metadata, and for the owner rename, sharing, links, delete.

    ``new_link_url`` is the URL of a link created by this very request. It is shown once and the
    page is ``no-store`` like every page (``SecurityHeadersMiddleware``), so neither the history
    nor a cache keeps it.

    Raises:
        NotFound: the file does not exist or the user may not see it.
    """
    item = await files.get_file(session, user, file_id)
    is_owner = can_modify_file(user, item.file)
    shared_with: list = []
    share_choices: list = []
    file_links: list = []
    if is_owner:
        file_links = await links.list_links(session, user, file_id)
        shared_with = await files.list_file_teams(session, user, file_id)
        already = {team.id for team in shared_with}
        # Only teams the owner belongs to can be chosen (section 11).
        share_choices = [t for t in await teams.list_my_teams(session, user) if t.id not in already]
    return render_page(
        request,
        settings,
        user,
        "file_detail.html",
        {
            "file": file_out(item, user.id),
            "links": file_links,
            "now": datetime.now(UTC),
            "new_link_url": new_link_url,
            "max_link_hours": settings.public_link_max_hours,
            "is_owner": is_owner,
            "can_delete": can_delete_file(user, item.file),
            "shared_with": shared_with,
            "share_choices": share_choices,
            "notice": notice,
            "errors": errors or [],
        },
        status_code=status_code,
    )


@router.get("/files/{file_id}")
@limit("read")
async def file_page(
    request: Request,
    file_id: uuid.UUID,
    user: PageUser,
    session: DbSession,
    settings: SettingsDep,
    renamed: bool = False,
) -> Response:
    """Show one file to its owner or to a member of a team it is shared with."""
    return await _file_page(
        request,
        session,
        settings,
        user,
        file_id,
        notice="File renamed." if renamed else None,
    )


@router.get("/files/{file_id}/download")
@limit("read")
async def download_page(
    request: Request,
    file_id: uuid.UUID,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    settings: SettingsDep,
    store: Store,
) -> Response:
    """Send the browser to a short-lived read-only URL of the blob."""
    url = await files.download_url(session, settings, store, user, file_id, ctx)
    return RedirectResponse(url, status_code=302)


@router.post("/files/{file_id}/rename", dependencies=[CsrfChecked])
@limit("write")
async def rename_submit(
    request: Request,
    file_id: uuid.UUID,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    settings: SettingsDep,
    filename: Annotated[str, Form()] = "",
) -> Response:
    """Rename the file (owner); an unusable name shows the page again with a message."""
    try:
        form = FileRenameIn.model_validate({"filename": filename})
    except ValidationError as exc:
        return await _file_page(
            request,
            session,
            settings,
            user,
            file_id,
            errors=validation_messages(exc),
            status_code=422,
        )
    await files.rename_file(session, user, file_id, form.filename, ctx)
    return see_other(f"/files/{file_id}?renamed=1")


@router.post("/files/{file_id}/delete", dependencies=[CsrfChecked])
@limit("write")
async def delete_submit(
    request: Request,
    file_id: uuid.UUID,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    store: Store,
    next_url: Annotated[str, Form(alias="next")] = "",
) -> Response:
    """Delete the file (owner or admin). ``next`` lets the admin list return to itself."""
    await files.delete_file(session, store, user, file_id, ctx)
    return see_other(safe_next(next_url, "/files"))


@router.post("/files/{file_id}/share", dependencies=[CsrfChecked])
@limit("write")
async def share_submit(
    request: Request,
    file_id: uuid.UUID,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    team_id: Annotated[int, Form(ge=1, le=MAX_ID)],
) -> Response:
    """Share the file with one of the owner's teams."""
    await files.share_with_team(session, user, file_id, team_id, ctx)
    return see_other(f"/files/{file_id}")


@router.post("/files/{file_id}/unshare", dependencies=[CsrfChecked])
@limit("write")
async def unshare_submit(
    request: Request,
    file_id: uuid.UUID,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    team_id: Annotated[int, Form(ge=1, le=MAX_ID)],
) -> Response:
    """Stop sharing the file with a team."""
    await files.unshare_from_team(session, user, file_id, team_id, ctx)
    return see_other(f"/files/{file_id}")


# --- Public links --------------------------------------------------------------------------------


@router.post("/files/{file_id}/links", dependencies=[CsrfChecked])
@limit("write")
async def create_link_submit(
    request: Request,
    file_id: uuid.UUID,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    settings: SettingsDep,
    expires_in_hours: Annotated[str, Form()] = "24",
) -> Response:
    """Create a public link and show its URL on the re-rendered page, this one time only.

    There is no redirect: a redirect would need the URL in a query string or the session, and
    the URL is a secret. Problems (bad lifetime, too many links) show the page with a message.
    """
    try:
        form = LinkCreateIn.model_validate({"expires_in_hours": expires_in_hours})
        link, token = await links.create_link(
            session, settings, user, file_id, form.expires_in_hours, ctx
        )
    except ValidationError as exc:
        errors = validation_messages(exc)
        return await _file_page(
            request, session, settings, user, file_id, errors=errors, status_code=422
        )
    except ValidationFailed as exc:
        return await _file_page(
            request, session, settings, user, file_id, errors=_messages(exc), status_code=422
        )
    except LinkLimit as exc:
        return await _file_page(
            request, session, settings, user, file_id, errors=[exc.detail], status_code=409
        )
    return await _file_page(
        request,
        session,
        settings,
        user,
        file_id,
        notice="Link created. Copy it now: it is not shown again.",
        new_link_url=link_url(settings.base_url, token),
    )


@router.post("/links/{link_id}/revoke", dependencies=[CsrfChecked])
@limit("write")
async def revoke_link_submit(
    request: Request,
    link_id: IntId,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    next_url: Annotated[str, Form(alias="next")] = "",
) -> Response:
    """Revoke a link (owner or admin) and go back to the file page, or to ``next``.

    An admin who does not own the file cannot open its page, so they go to the admin file list.
    """
    file = await links.revoke_link(session, user, link_id, ctx)
    default = f"/files/{file.id}" if file.owner_id == user.id else "/admin/files"
    return see_other(safe_next(next_url, default))
