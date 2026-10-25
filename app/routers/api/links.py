"""Public link endpoints of the JSON API (create, list, revoke).

The link URL is returned only by ``POST /files/{id}/links``; listings contain neither the token
nor the URL. Opening a link (``/s/{token}``) is in ``routers/public.py``.
"""

import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.ratelimit import limit
from app.routers.common import ApiUser, AuditCtx, DbSession, IntId, SettingsDep, link_url
from app.schemas.links import LinkCreatedOut, LinkCreateIn, LinkOut
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


@router.delete("/links/{link_id}", status_code=204)
@limit("write")
async def revoke_link(
    request: Request, link_id: IntId, user: ApiUser, ctx: AuditCtx, session: DbSession
) -> None:
    """Revoke a link (owner or admin). Revoking twice is fine."""
    await links.revoke_link(session, user, link_id, ctx)
