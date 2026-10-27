"""Public download link endpoint ``/s/{token}`` (no login).

Every failure (malformed, unknown, expired, revoked link, disabled owner) is the same 404 page.
All responses, including the error pages, carry headers that keep the token out of the
browser's referrer, caches and search engines.
"""

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse

from app.errors import NotFound, StorageUnavailable
from app.ratelimit import limit
from app.routers.common import DbSession, SettingsDep, Store, client_ip, request_id, templates
from app.services import links
from app.services.audit import AuditContext

router = APIRouter(tags=["public"])

# Referrer-Policy: the token in the URL is not sent on to other sites. no-store: no cache keeps
# the redirect. noindex: search engines skip it.
PUBLIC_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex",
}


def _error_page(request: Request, status_code: int, message: str) -> Response:
    """The normal error page, but with the privacy headers (the generic handler has none)."""
    return templates.TemplateResponse(
        request,
        "error.html",
        {"user": None, "csrf_token": "", "status_code": status_code, "message": message},
        status_code=status_code,
        headers=PUBLIC_HEADERS,
    )


@router.get("/s/{token}", include_in_schema=False)
@limit("public")
async def public_download(
    request: Request, token: str, session: DbSession, settings: SettingsDep, store: Store
) -> Response:
    """Redirect to a fresh short-lived download URL if the link is valid, else a 404 page."""
    ctx = AuditContext.anonymous(ip=client_ip(request), request_id=request_id(request))
    try:
        url = await links.resolve_public_link(session, settings, store, token, ctx)
    except NotFound:
        return _error_page(request, 404, "Page not found.")
    except StorageUnavailable as exc:
        return _error_page(request, exc.status_code, exc.detail)
    return RedirectResponse(url, status_code=302, headers=PUBLIC_HEADERS)
