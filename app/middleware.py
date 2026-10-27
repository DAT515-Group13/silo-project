"""Cookies, Origin checks and cookie refresh for the HTML pages.

The page surface authenticates with cookies, the API with Bearer tokens; the two never mix. The
request ID, security header and trusted host middleware are added in phase 6.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import Settings
from app.errors import CsrfFailed
from app.services.sessions import IssuedTokens

DEFAULT_NEXT = "/files"


@dataclass(frozen=True)
class CookieNames:
    """Names of the three cookies of the page surface."""

    access: str
    refresh: str
    csrf: str


def cookie_names(settings: Settings) -> CookieNames:
    """Return the cookie names.

    The ``__Host-`` prefix makes browsers accept the cookie only if it is Secure, has Path=/ and
    no Domain attribute, so a sibling subdomain cannot plant or overwrite it. It needs HTTPS, so
    it is dropped when ``COOKIE_SECURE=false`` (local development only).
    """
    prefix = "__Host-" if settings.cookie_secure else ""
    return CookieNames(
        access=f"{prefix}access_token",
        refresh=f"{prefix}refresh_token",
        csrf=f"{prefix}csrf_token",
    )


def set_auth_cookies(response: Response, settings: Settings, tokens: IssuedTokens) -> None:
    """Store a token pair in cookies: HttpOnly, Secure, Path=/, no Domain.

    The access cookie is SameSite=Lax so that following a link from another site keeps you
    logged in. The refresh cookie is SameSite=Strict: it is only sent with requests that start
    on this site, and it is used for nothing else than refreshing.
    """
    names = cookie_names(settings)
    response.set_cookie(
        names.access,
        tokens.access_token,
        max_age=tokens.expires_in,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.set_cookie(
        names.refresh,
        tokens.refresh_token,
        max_age=tokens.refresh_expires_in,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def clear_auth_cookies(response: Response, settings: Settings) -> None:
    """Delete the access and refresh cookies (logout, or cookies that no longer work)."""
    names = cookie_names(settings)
    for name, samesite in ((names.access, "lax"), (names.refresh, "strict")):
        response.delete_cookie(
            name, path="/", secure=settings.cookie_secure, httponly=True, samesite=samesite
        )


def set_csrf_cookie(response: Response, settings: Settings, token: str) -> None:
    """Store the CSRF token for the double-submit check.

    The form field carries the same value. The cookie is HttpOnly because the server writes the
    field into the page itself; no script ever needs to read it.
    """
    response.set_cookie(
        cookie_names(settings).csrf,
        token,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _origin_of(url: str) -> tuple[str, str, int | None]:
    """Scheme, lower-case host and port of a URL; the default port counts as given.

    ``https://x`` and ``https://x:443`` are the same origin for a browser, which sends the
    shorter form.
    """
    parts = urlsplit(url)
    default = {"http": 80, "https": 443}.get(parts.scheme)
    return parts.scheme, (parts.hostname or "").lower(), parts.port or default


def check_origin(request: Request, settings: Settings) -> None:
    """Reject a POST that did not come from this site.

    ``Origin`` (or, if missing, ``Referer``) must be the origin of ``BASE_URL``. A browser always
    sends one of them on a form POST, so a request with neither is refused. If the browser sends
    ``Sec-Fetch-Site``, it must say ``same-origin``.

    Raises:
        CsrfFailed: if any check fails.
    """
    sender = request.headers.get("origin") or request.headers.get("referer")
    if not sender or sender == "null":
        raise CsrfFailed
    try:
        if _origin_of(sender) != _origin_of(settings.base_url):
            raise CsrfFailed
    except ValueError:  # a malformed port in the header
        raise CsrfFailed from None
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site != "same-origin":
        raise CsrfFailed


def safe_next(value: str | None, default: str = DEFAULT_NEXT) -> str:
    """Return ``value`` if it is a path on this site, else ``default`` (open redirect guard).

    Only a relative path starting with a single ``/`` is accepted. ``//host`` and
    ``/\\host`` are treated as absolute URLs by browsers, so they are refused as well.
    """
    if not value or not value.startswith("/") or value.startswith(("//", "/\\")):
        return default
    if any(ord(char) < 32 or char == "\\" for char in value):
        return default
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return default
    return value


def mark_logged_out(request: Request) -> None:
    """Have ``AuthCookieMiddleware`` delete the auth cookies of this response.

    Page routes that end the current session (logout, logout-all, revoking this session) call
    this instead of deleting the cookies themselves: the page dependency may have refreshed the
    session earlier in the same request, and the middleware would otherwise put the new cookies
    of the now revoked session back after the route deleted them.
    """
    request.state.refreshed_tokens = None
    request.state.clear_auth_cookies = True


def mark_logged_in(request: Request, tokens: IssuedTokens) -> None:
    """Have ``AuthCookieMiddleware`` set the cookies of a new session on this response.

    The login route calls this instead of setting the cookies itself: the CSRF check ran the
    page dependency first, and if the browser sent dead auth cookies it asked the middleware to
    delete them. Deleting after the route set the new cookies would log the user out again.
    """
    request.state.refreshed_tokens = tokens
    request.state.clear_auth_cookies = False


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
# Swagger UI loads scripts and styles from a CDN, which the strict CSP would block; the docs
# exist only in local and dev (ENABLE_DOCS).
CSP_EXEMPT_PREFIXES = ("/docs", "/redoc", "/openapi.json")
# Bootstrap is the only thing worth caching; every other response may contain private data.
CACHEABLE_PREFIX = "/static/"


class SecurityHeadersMiddleware:
    """Add the response headers of spec section 12 to every response.

    Outermost middleware, so error pages and the 413 of ``BodyLimitMiddleware`` get them too.
    A header a route set itself (for example the ``no-store`` of ``/s/{token}``) is kept.
    Responses of Starlette's own last-resort 500 handler sit outside every middleware and do not
    get them.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope["path"]

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    if name == "Content-Security-Policy" and path.startswith(CSP_EXEMPT_PREFIXES):
                        continue
                    headers.setdefault(name, value)
                # Pages and API answers must not be kept by browsers or proxies: after logout the
                # back button would otherwise show file lists.
                if not path.startswith(CACHEABLE_PREFIX):
                    headers.setdefault("Cache-Control", "no-store")
            await send(message)

        await self.app(scope, receive, send_with_headers)


# Only the two upload routes stream large bodies (to blob storage, never to disk). Everything
# else is a small form or JSON document.
MAX_BODY_BYTES = 64 * 1024
UNLIMITED_BODY_ROUTES = {("POST", "/api/v1/files"), ("POST", "/files/upload")}


class BodyLimitMiddleware:
    """Refuse request bodies over ``MAX_BODY_BYTES`` except on the upload routes.

    FastAPI reads a form or JSON body before any dependency runs, and Starlette writes multipart
    file parts to the local disk, so without this limit an anonymous ``POST /login`` with a huge
    body fills the disk or memory before the Origin check, CSRF check or rate limit run.
    Written as plain ASGI (not ``BaseHTTPMiddleware``) so it never buffers the body itself.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or (scope["method"], scope["path"]) in UNLIMITED_BODY_ROUTES:
            await self.app(scope, receive, send)
            return

        # A declared size is checked first, so an honest oversized client is refused unread.
        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            # The API keeps its JSON error shape (section 9.5); pages get plain text.
            if scope["path"].startswith("/api/"):
                body = {"detail": "Request body too large.", "code": "payload_too_large"}
                await JSONResponse(body, status_code=413)(scope, receive, send)
            else:
                await PlainTextResponse("Request body too large.", status_code=413)(
                    scope, receive, send
                )
            return

        # Content-Length can be missing (chunked) or false, so the bytes are counted as well.
        # FastAPI's body reader passes an HTTPException through, and the app's HTTP error
        # handler renders it as a 413. This middleware must sit inside AuthCookieMiddleware:
        # BaseHTTPMiddleware wraps errors raised in receive, which would turn into a 400.
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > MAX_BODY_BYTES:
                    raise HTTPException(status_code=413, detail="Request body too large.")
            return message

        await self.app(scope, limited_receive, send)


class AuthCookieMiddleware(BaseHTTPMiddleware):
    """Attach cookie changes decided during a request to its response.

    The page authentication dependency may refresh an expired session (new tokens) or find the
    cookies useless (to be deleted). It cannot reliably edit the response, because the route may
    return a redirect object, so it leaves a note on ``request.state`` and this middleware
    applies it to whatever response comes out.

    ``BaseHTTPMiddleware`` can buffer request bodies, but only if ``dispatch`` reads the body.
    This one never does (Starlette passes the stream through untouched), so uploads still stream
    to blob storage; keep it that way when editing ``dispatch``.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        settings: Settings = request.app.state.settings
        refreshed: IssuedTokens | None = getattr(request.state, "refreshed_tokens", None)
        if refreshed is not None:
            set_auth_cookies(response, settings, refreshed)
        elif getattr(request.state, "clear_auth_cookies", False):
            clear_auth_cookies(response, settings)
        return response
