"""Public link endpoints of the JSON API (create, list, revoke).

The link URL is returned only by ``POST /files/{id}/links``; listings contain neither the token
nor the URL. Opening a link (``/s/{token}``) is in ``routers/public.py``.
"""

import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.ratelimit import limit
from app.routers.common import (
    ApiUser,
    AuditCtx,
    DbSession,
    IntId,
    PageNumber,
    PageSize,
    SettingsDep,
    link_url,
)
from app.schemas.common import Page
from app.schemas.links import LinkCreatedOut, LinkCreateIn, LinkExpiryIn, LinkOut, MyLinkOut
from app.services import links

router = APIRouter(prefix="/api/v1", tags=["links"])


@router.post("/files/{file_id}/links", status_code=201, response_model=LinkCreatedOut)
@limit("write")
async def create_link(
    request: Request,
    file_id: uuid.UUID,
    body: LinkCreateIn,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
    settings: SettingsDep,
) -> JSONResponse:
    """Create a public link (owner only). The URL is shown only in this response.

    Errors: 404 for no access, 409 `link_limit` (10 active links), 422 for a lifetime above
    `PUBLIC_LINK_MAX_HOURS`.
    """
    link, token = await links.create_link(
        session, settings, user, file_id, body.expires_in_hours, ctx
    )
    created = LinkCreatedOut(
        id=link.id, url=link_url(settings.base_url, token), expires_at=link.expires_at
    )
    # no-store: the response contains the only copy of the URL, so no cache may keep it.
    return JSONResponse(
        created.model_dump(mode="json"), status_code=201, headers={"Cache-Control": "no-store"}
    )


@router.get("/files/{file_id}/links", response_model=list[LinkOut])
@limit("read")
async def list_links(
    request: Request, file_id: uuid.UUID, user: ApiUser, session: DbSession
) -> list[LinkOut]:
    """Links of a file with expiry, revocation and download count; no tokens or URLs."""
    return [
        LinkOut(
            id=link.id,
            expires_at=link.expires_at,
            revoked_at=link.revoked_at,
            download_count=link.download_count,
            created_at=link.created_at,
        )
        for link in await links.list_links(session, user, file_id)
    ]


@router.get("/links", response_model=Page[MyLinkOut])
@limit("read")
async def list_my_links(
    request: Request,
    user: ApiUser,
    session: DbSession,
    page: PageNumber = 1,
    size: PageSize = 20,
) -> Page[MyLinkOut]:
    """All links of my files, newest first, paginated; no tokens or URLs."""
    rows, total = await links.list_my_links(session, user, page=page, size=size)
    items = [
        MyLinkOut(
            id=link.id,
            expires_at=link.expires_at,
            revoked_at=link.revoked_at,
            download_count=link.download_count,
            created_at=link.created_at,
            file_id=file.id,
            filename=file.filename,
        )
        for link, file in rows
    ]
    return Page[MyLinkOut](items=items, total=total, page=page, size=size)


@router.patch("/links/{link_id}", response_model=LinkOut)
@limit("write")
async def change_link_expiry(
    request: Request,
    link_id: IntId,
    body: LinkExpiryIn,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
    settings: SettingsDep,
) -> LinkOut:
    """Set a new expiry (hours from now) on an active link (owner only).

    Errors: 404 for no access, 422 for a lifetime above `PUBLIC_LINK_MAX_HOURS` or for a link
    that is expired or revoked.
    """
    link = await links.change_expiry(session, settings, user, link_id, body.expires_in_hours, ctx)
    return LinkOut(
        id=link.id,
        expires_at=link.expires_at,
        revoked_at=link.revoked_at,
        download_count=link.download_count,
        created_at=link.created_at,
    )


@router.delete("/links/{link_id}", status_code=204)
@limit("write")
async def revoke_link(
    request: Request, link_id: IntId, user: ApiUser, ctx: AuditCtx, session: DbSession
) -> None:
    """Revoke a link (owner or admin). Revoking twice is fine."""
    await links.revoke_link(session, user, link_id, ctx)
