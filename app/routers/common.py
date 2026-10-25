"""Dependencies and helpers shared by all routers.

B's routers import everything they need from here, so they never reach into A's modules.
Two authentication surfaces exist and never mix: ``ApiUser`` (Bearer header, for
``/api/v1``) and ``PageUser`` (cookies, for the HTML pages).
"""

import hmac
import ipaddress
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

from fastapi import Depends, HTTPException, Query, Request, Response
from fastapi import Path as PathParam
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db import get_db
from app.errors import CsrfFailed, InvalidToken, RefreshInProgress
from app.middleware import check_origin, cookie_names, set_csrf_cookie
from app.models import AuthSession, User, UserStatus
from app.permissions import CurrentUser
from app.schemas.common import UserRefOut
from app.schemas.files import FileOut
from app.security import create_csrf_token, decode_access_token, verify_csrf_token
from app.services import sessions
from app.services.audit import AuditContext
from app.services.teams import FileItem
from app.storage.base import BlobStore

APP_DIR = Path(__file__).resolve().parent.parent
# Jinja2 autoescaping is on for .html templates.
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

# CSRF tokens of the login and register forms are not tied to a session.
PRE_SESSION_BINDING = "pre-session"


# --- API authentication (Bearer) -----------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)


def bearer_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    """Extract the Bearer token. Cookies are never accepted on /api/v1.

    Raises:
        InvalidToken: if the header is missing, has another scheme or is empty.

    Only extracts the token; ``get_current_api_user`` verifies it.
    """
    if credentials is None or not credentials.credentials:
        raise InvalidToken
    return credentials.credentials


async def authenticate_access_token(
    session: AsyncSession, settings: Settings, token: str
) -> CurrentUser:
    """Check an access token and its session.

    Used for the Bearer header and for the access cookie alike.

    Raises:
        InvalidToken: for every failure, always the same, so a client cannot tell a bad
            signature from a revoked session or a disabled account.

    Side effect: updates ``auth_sessions.last_used_at`` at most once a minute (step 6).
    """
    # Step 2: signature, algorithm, claims and expiry. Current secret first, then the previous
    # one during rotation.
    secrets = [settings.jwt_secret.get_secret_value()]
    if settings.jwt_secret_previous is not None:
        secrets.append(settings.jwt_secret_previous.get_secret_value())
    claims = decode_access_token(
        token, secrets=secrets, issuer=settings.jwt_issuer, audience=settings.jwt_audience
    )

    # The transaction is closed before the route runs: services open their own with
    # `session.begin()`, which fails if one is already open on this request's session.
    async with session.begin():
        # Step 3: one JOIN loads the user (`sub`) and the session (`sid`). The user condition
        # on both sides also rejects a token whose `sid` belongs to someone else.
        row = (
            await session.execute(
                select(User, AuthSession)
                .join(AuthSession, AuthSession.user_id == User.id)
                .where(User.id == claims.user_id, AuthSession.id == claims.session_id)
            )
        ).first()
        if row is None:
            raise InvalidToken
        user, auth_session = row

        # Step 4: the session is the revocation switch (logout works immediately); the user
        # status is read now, so disabling an account also takes effect immediately.
        now = datetime.now(UTC)
        if auth_session.revoked_at is not None or auth_session.expires_at <= now:
            raise InvalidToken
        if user.status != UserStatus.active:
            raise InvalidToken

        # Step 6: record activity, at most once a minute.
        await sessions.touch(session, auth_session.id, now=now)

    # The role comes from the database row, never from the token.
    return CurrentUser(
        id=user.id, username=user.username, role=user.role, session_id=auth_session.id
    )


async def get_current_api_user(
    request: Request,
    token: Annotated[str, Depends(bearer_token)],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> CurrentUser:
    """Authenticate an API request: Bearer token only, cookies are never looked at (step 1).

    Raises:
        InvalidToken: see ``authenticate_access_token``; the handler adds
            ``WWW-Authenticate: Bearer``.

    Object-level authorization (step 5) is up to the route's service.
    """
    user = await authenticate_access_token(session, settings, token)
    # The per-user rate limits (ratelimit.py) key on this value.
    request.state.user_id = user.id
    return user


# --- Page authentication (cookies) ---------------------------------------------------------------


async def get_optional_page_user(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> CurrentUser | None:
    """Return the logged-in user of a page request, or None if nobody is logged in.

    Reads the access cookie (step 1 of the token checks, for pages). If it is missing or no longer
    valid but a refresh cookie exists, the session is refreshed transparently: the rotated
    tokens are left on ``request.state`` and ``AuthCookieMiddleware`` puts them in the response.
    Cookies that lead nowhere are scheduled for deletion.
    """
    names = cookie_names(settings)
    access = request.cookies.get(names.access)
    refresh = request.cookies.get(names.refresh)

    user: CurrentUser | None = None
    refresh_in_progress = False
    if access:
        try:
            user = await authenticate_access_token(session, settings, access)
        except InvalidToken:
            user = None  # expired or revoked: try the refresh token below

    if user is None and refresh:
        tokens = None
        try:
            tokens = await sessions.rotate_refresh(
                session,
                settings,
                refresh,
                ip=client_ip(request),
                request_id=request_id(request),
            )
        except InvalidToken:
            pass  # the session is over: the cookies are deleted below
        except RefreshInProgress:
            # A parallel request refreshes this session right now and its response carries
            # the new cookies. This request is treated as logged out, but it must not delete
            # the cookies: if its response arrived last, the browser would lose the new tokens.
            refresh_in_progress = True
            request.state.refresh_in_progress = True  # read by main._login_redirect
        if tokens is not None:
            request.state.refreshed_tokens = tokens
            user = CurrentUser(tokens.user_id, tokens.username, tokens.role, tokens.session_id)

    if user is None:
        if (access or refresh) and not refresh_in_progress:
            request.state.clear_auth_cookies = True
        return None
    request.state.user_id = user.id
    request.state.session_id = user.session_id
    return user


async def get_current_page_user(
    user: Annotated[CurrentUser | None, Depends(get_optional_page_user)],
) -> CurrentUser:
    """Require a logged-in user on a page; otherwise ``InvalidToken`` (redirect to /login)."""
    if user is None:
        raise InvalidToken
    return user


async def verify_origin(
    request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> None:
    """Dependency form of ``check_origin``; listed first so it runs before any database work."""
    check_origin(request, settings)


async def require_csrf(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    _origin: Annotated[None, Depends(verify_origin)],
    user: Annotated[CurrentUser | None, Depends(get_optional_page_user)],
) -> None:
    """CSRF protection of every page POST.

    Signed double submit: the token in the ``csrf_token`` form field must equal the CSRF cookie,
    and its signature must match the session it was issued for (or the pre-session value on the
    login and register forms). The Origin check has already run.

    Raises:
        CsrfFailed: if anything is missing, differs or does not verify.
    """
    cookie = request.cookies.get(cookie_names(settings).csrf)
    form = await request.form()
    field = form.get("csrf_token")
    if not cookie or not isinstance(field, str) or not field:
        raise CsrfFailed

    # Constant-time comparison, so response time does not leak how much of the token matched.
    if not hmac.compare_digest(cookie.encode(), field.encode()):
        raise CsrfFailed

    # A token for another session, or one made without CSRF_SECRET, does not verify.
    binding = str(user.session_id) if user else PRE_SESSION_BINDING
    if not verify_csrf_token(
        field, secret=settings.csrf_secret.get_secret_value(), binding=binding
    ):
        raise CsrfFailed


def render_page(
    request: Request,
    settings: Settings,
    user: CurrentUser | None,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
) -> Response:
    """Render a template with the standard context and set the matching CSRF cookie.

    The template gets ``user`` (or None) and ``csrf_token``, which every form must repeat in a
    hidden field named ``csrf_token``. The token is tied to the user's session, or to the
    pre-session value for anonymous visitors.
    """
    binding = str(user.session_id) if user else PRE_SESSION_BINDING
    secret = settings.csrf_secret.get_secret_value()

    # Reuse the cookie's token while it is still valid for this binding. A new token on every
    # render would replace the cookie and break the forms of every other open tab (403).
    token = request.cookies.get(cookie_names(settings).csrf)
    is_new = not token or not verify_csrf_token(token, secret=secret, binding=binding)
    if is_new:
        token = create_csrf_token(secret, binding)

    response = templates.TemplateResponse(
        request,
        template,
        {"user": user, "csrf_token": token, **(context or {})},
        status_code=status_code,
    )
    if is_new:
        set_csrf_cookie(response, settings, token)
    return response


# --- Shared helpers ------------------------------------------------------------------------------


def client_ip(request: Request) -> str | None:
    """Return the client IP, or None if it is not a valid address.

    Behind Traefik, uvicorn's ``--proxy-headers`` already replaced the peer address with the
    forwarded one (only for trusted proxies, ``FORWARDED_ALLOW_IPS``). The value goes into
    ``inet`` columns, so anything that is not an IP address is dropped instead of failing.
    """
    host = request.client.host if request.client else None
    try:
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None


def request_id(request: Request) -> str | None:
    """Return the request ID once the request-ID middleware exists (phase 6), else None."""
    return getattr(request.state, "request_id", None)


def get_audit_context(
    request: Request, user: Annotated[CurrentUser, Depends(get_current_api_user)]
) -> AuditContext:
    """Audit context of an authenticated API request: the user, their IP and the request ID."""
    return AuditContext.for_user(
        user.id, user.username, ip=client_ip(request), request_id=request_id(request)
    )


def get_page_audit_context(
    request: Request, user: Annotated[CurrentUser, Depends(get_current_page_user)]
) -> AuditContext:
    """Audit context of an authenticated page request (same content as for the API)."""
    return AuditContext.for_user(
        user.id, user.username, ip=client_ip(request), request_id=request_id(request)
    )


def get_blob_store(request: Request) -> BlobStore:
    """Return the BlobStore created by the lifespan (or injected in tests)."""
    return request.app.state.blob_store


def see_other(url: str) -> RedirectResponse:
    """Redirect after a page POST (or GET) with 303, so the browser follows with a GET."""
    return RedirectResponse(url, status_code=303)


def validation_messages(error: ValidationError) -> list[str]:
    """Readable messages of a pydantic error, without the submitted values (may be a password)."""
    return [str(item["msg"]).removeprefix("Value error, ") for item in error.errors()]


def file_out(item: FileItem, viewer_id: int) -> FileOut:
    """Build the file metadata of example 9.3; never includes the blob name."""
    file = item.file
    return FileOut(
        id=file.id,
        filename=file.filename,
        content_type=file.content_type,
        size_bytes=file.size_bytes,
        owner=UserRefOut(id=file.owner_id, username=item.owner_username),
        is_owner=file.owner_id == viewer_id,
        created_at=file.created_at,
    )


def not_implemented() -> NoReturn:
    """Answer 501 for endpoints that are still skeletons."""
    raise HTTPException(status_code=501, detail="Not implemented.")


BearerToken = Annotated[str, Depends(bearer_token)]
ApiUser = Annotated[CurrentUser, Depends(get_current_api_user)]
PageUser = Annotated[CurrentUser, Depends(get_current_page_user)]
OptionalPageUser = Annotated[CurrentUser | None, Depends(get_optional_page_user)]
CsrfChecked = Depends(require_csrf)  # use as `dependencies=[CsrfChecked]` on every page POST
AuditCtx = Annotated[AuditContext, Depends(get_audit_context)]
PageAuditCtx = Annotated[AuditContext, Depends(get_page_audit_context)]
DbSession = Annotated[AsyncSession, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
Store = Annotated[BlobStore, Depends(get_blob_store)]

# page >= 1 and 1 <= size <= 100.
PageNumber = Annotated[int, Query(ge=1, le=1_000_000)]
PageSize = Annotated[int, Query(ge=1, le=100)]

# Database IDs are 32-bit integers: a larger value in a URL would be an error from the driver (500).
MAX_ID = 2_147_483_647
IntId = Annotated[int, PathParam(ge=1, le=MAX_ID)]
