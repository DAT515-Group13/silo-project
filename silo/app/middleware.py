"""Cookies, Origin checks and cookie refresh for the HTML pages.

The page surface authenticates with cookies, the API with Bearer tokens; the two never mix. The
request ID, security header and trusted host middleware are added in phase 6.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

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


def check_origin(request: Request, settings: Settings) -> None:
    """Reject a POST that did not come from this site.

    ``Origin`` (or, if missing, ``Referer``) must be the origin of ``BASE_URL``. A browser always
    sends one of them on a form POST, so a request with neither is refused. If the browser sends
    ``Sec-Fetch-Site``, it must say ``same-origin``.

    Raises:
        CsrfFailed: if any check fails.
    """
    expected = urlsplit(settings.base_url)
    sender = request.headers.get("origin") or request.headers.get("referer")
    if not sender or sender == "null":
        raise CsrfFailed
    actual = urlsplit(sender)
    if (actual.scheme, actual.netloc.lower()) != (expected.scheme, expected.netloc.lower()):
        raise CsrfFailed
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


class AuthCookieMiddleware(BaseHTTPMiddleware):
    """Attach cookie changes decided during a request to its response.

    The page authentication dependency may refresh an expired session (new tokens) or find the
    cookies useless (to be deleted). It cannot reliably edit the response, because the route may
    return a redirect object, so it leaves a note on ``request.state`` and this middleware
    applies it to whatever response comes out.
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
