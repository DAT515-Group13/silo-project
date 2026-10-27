"""File endpoints of the JSON API.

Routers only parse the request, call one service function and build the response. All access
rules live in ``services/files.py`` and ``permissions.py``. Uploads are not parsed by FastAPI
(no ``UploadFile``, which would spool large files to disk): ``MultipartReader`` streams the file
part straight to blob storage.
"""

import uuid

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from app.errors import FileTooLarge, QuotaExceeded, ValidationFailed
from app.ratelimit import limit, upload_slot
from app.routers.common import (
    ApiUser,
    AuditCtx,
    DbSession,
    IntId,
    PageNumber,
    PageSize,
    SettingsDep,
    Store,
    declared_size,
    file_out,
)
from app.routers.multipart import MultipartReader, drain_refused_upload
from app.schemas.common import Page
from app.schemas.files import FileOut, FileRenameIn, FileTeamOut
from app.services import files

router = APIRouter(prefix="/api/v1", tags=["files"])


@router.get("/files", response_model=Page[FileOut])
@limit("read")
async def list_files(
    request: Request,
    user: ApiUser,
    session: DbSession,
    scope: files.Scope = "mine",
    sort: files.Sort = "-created_at",
    page: PageNumber = 1,
    size: PageSize = 20,
) -> Page[FileOut]:
    """My files, or files shared with my teams (`?scope=shared`), sorted and paginated."""
    items, total = await files.list_files(
        session, user, scope=scope, sort=sort, page=page, size=size
    )
    return Page[FileOut](
        items=[file_out(item, user.id) for item in items], total=total, page=page, size=size
    )


@router.post("/files", status_code=201, response_model=FileOut)
@limit("upload")
async def upload_file(
    request: Request,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
    settings: SettingsDep,
    store: Store,
) -> FileOut:
    """Upload one file as multipart field `file`.

    Errors: 413 `file_too_large` or `quota_exceeded`, 422 for a malformed body, 429 when the
    user already has 3 uploads running, 503 `storage_unavailable`.
    """
    # At most 3 uploads at the same time per user.
    body = request.stream()
    try:
        async with upload_slot(user.id):
            reader = MultipartReader(request.headers.get("content-type", ""), body, max_parts=1)
            part = await reader.next_part()
            if part is None or part.name != "file" or part.filename is None:
                raise ValidationFailed([{"field": "file", "message": "Field 'file' is required."}])
            item = await files.upload(
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
    except (FileTooLarge, QuotaExceeded):
        # Let the client finish sending, or the proxy may turn this 413 into a 502.
        await drain_refused_upload(
            body, declared_size=declared_size(request), max_file_bytes=settings.max_file_size_bytes
        )
        raise
    return file_out(item, user.id)


@router.get("/files/{file_id}", response_model=FileOut)
@limit("read")
async def get_file(
    request: Request, file_id: uuid.UUID, user: ApiUser, session: DbSession
) -> FileOut:
    """Metadata of a file. Owner or team member; everybody else gets 404."""
    return file_out(await files.get_file(session, user, file_id), user.id)


@router.patch("/files/{file_id}", response_model=FileOut)
@limit("write")
async def rename_file(
    request: Request,
    file_id: uuid.UUID,
    body: FileRenameIn,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
) -> FileOut:
    """Rename a file (owner only)."""
    return file_out(await files.rename_file(session, user, file_id, body.filename, ctx), user.id)


@router.get("/files/{file_id}/download", status_code=302)
@limit("read")
async def download_file(
    request: Request,
    file_id: uuid.UUID,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
    settings: SettingsDep,
    store: Store,
) -> RedirectResponse:
    """Redirect to a short-lived read-only URL of the blob (owner or team member)."""
    url = await files.download_url(session, settings, store, user, file_id, ctx)
    return RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})


@router.delete("/files/{file_id}", status_code=204)
@limit("write")
async def delete_file(
    request: Request,
    file_id: uuid.UUID,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
    store: Store,
) -> None:
    """Delete a file (owner or admin) and free the owner's quota."""
    await files.delete_file(session, store, user, file_id, ctx)


@router.get("/files/{file_id}/teams", response_model=list[FileTeamOut])
@limit("read")
async def list_file_teams(
    request: Request, file_id: uuid.UUID, user: ApiUser, session: DbSession
) -> list[FileTeamOut]:
    """Teams the file is shared with (owner only)."""
    teams = await files.list_file_teams(session, user, file_id)
    return [FileTeamOut(id=team.id, name=team.name) for team in teams]


@router.put("/files/{file_id}/teams/{team_id}", status_code=204)
@limit("write")
async def share_file(
    request: Request,
    file_id: uuid.UUID,
    team_id: IntId,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
) -> None:
    """Share the file with a team the owner belongs to. Idempotent."""
    await files.share_with_team(session, user, file_id, team_id, ctx)


@router.delete("/files/{file_id}/teams/{team_id}", status_code=204)
@limit("write")
async def unshare_file(
    request: Request,
    file_id: uuid.UUID,
    team_id: IntId,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
) -> None:
    """Stop sharing the file with a team (owner only). Idempotent."""
    await files.unshare_from_team(session, user, file_id, team_id, ctx)
