"""App factory, lifespan and exception handlers.

Run with: ``uvicorn app.main:create_app --factory``. The lifespan owns the database engine and
the BlobStore. Errors are rendered as JSON under ``/api/`` and as HTML pages elsewhere. The
request ID and trusted host middleware are added in phase 6.
"""

import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import Settings, get_settings
from app.db import create_engine, create_session_factory
from app.errors import InvalidToken, RateLimited, SiloError, ValidationFailed
from app.middleware import (
    AuthCookieMiddleware,
    BodyLimitMiddleware,
    SecurityHeadersMiddleware,
    clear_auth_cookies,
)
from app.ratelimit import limiter, rate_limit_handler, reset_limits
from app.routers import admin_pages, file_pages, health, pages, public, team_pages
from app.routers.api import api_router
from app.routers.common import APP_DIR, templates
from app.routers.public import PUBLIC_HEADERS
from app.services.users import ensure_initial_admin
from app.storage.azure_blob import create_blob_store
from app.storage.base import BlobStore

logger = logging.getLogger("silo")

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class RedactLinkTokens(logging.Filter):
    """Hide public link tokens in uvicorn's access log.

    Uvicorn logs the request path of every request, and for ``/s/<token>`` that path is the
    secret that lets anybody download the file. The log line becomes ``/s/[redacted]``.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Uvicorn's access records have the arguments (client, method, path, http_version, status).
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            redacted = re.sub(r"^/s/[^?]*", "/s/[redacted]", args[2])
            record.args = (*args[:2], redacted, *args[3:])
        return True


def configure_logging() -> None:
    """Send the app's log records (logger ``silo``, INFO and up) to stderr.

    Uvicorn configures only its own loggers, so without this the app's INFO messages were
    dropped and warnings printed without time or level. Records still propagate to the root
    logger, where nothing is attached in production and pytest's ``caplog`` listens in tests.
    The handler is added once, however many apps a process creates (the tests create many).
    """
    # Added once, however many apps a process creates.
    access_logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, RedactLinkTokens) for f in access_logger.filters):
        access_logger.addFilter(RedactLinkTokens())
    if any(getattr(handler, "_silo", False) for handler in logger.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler._silo = True  # type: ignore[attr-defined]  # marks the handler as ours
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# Codes for plain HTTP errors; not part of the domain error list.
_HTTP_CODES = {
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
}

# What the HTML error page says for plain HTTP errors.
_PAGE_MESSAGES = {
    404: "Page not found.",
    405: "This action is not allowed here.",
}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create the database engine and the BlobStore at startup, release them at shutdown.

    A BlobStore passed to ``create_app`` belongs to the caller and is not closed here.
    The engine does not connect until the first query, so startup works without a database.
    """
    settings: Settings = app.state.settings
    engine = create_engine(settings)
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    owns_store = app.state.blob_store is None
    # Everything after the engine is inside the try, so a failed startup still disposes it.
    try:
        # "First admin": runs at every startup, does nothing if the account exists.
        # Tests without a database switch it off with create_app(initial_admin=False).
        if app.state.initial_admin:
            async with app.state.session_factory() as session:
                if await ensure_initial_admin(session, settings):
                    logger.info("Initial admin account created")

        if owns_store:
            app.state.blob_store = create_blob_store(settings)
        yield
    finally:
        if owns_store and app.state.blob_store is not None:
            await app.state.blob_store.close()
            app.state.blob_store = None
        await engine.dispose()


# --- Error handlers ----------------------------------------------------------------------------


def _is_api(request: Request) -> bool:
    """Errors under /api/ are JSON; everything else is a page for a browser."""
    return request.url.path.startswith("/api/")


def _error_page(
    request: Request, status_code: int, message: str, headers: dict[str, str] | None = None
) -> Response:
    """Render the HTML error page. It never contains a stack trace or request data."""
    return templates.TemplateResponse(
        request,
        "error.html",
        {"user": None, "csrf_token": "", "status_code": status_code, "message": message},
        status_code=status_code,
        headers=headers,
    )


def _login_redirect(request: Request) -> Response:
    """Send a visitor without a valid session to /login and drop their useless cookies.

    For a GET the page is remembered in ``next``; it is checked again by ``safe_next`` after the
    login. After a failed POST there is nothing sensible to come back to.
    """
    target = "/login"
    if request.method == "GET":
        path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        target = f"/login?next={quote(path, safe='/')}"
    response = RedirectResponse(target, status_code=303)
    # Keep the cookies while a parallel request is refreshing this session: its response
    # carries the new ones, and deleting them here could log the user out (see
    # get_optional_page_user).
    if not getattr(request.state, "refresh_in_progress", False):
        clear_auth_cookies(response, request.app.state.settings)
    return response


async def _silo_error_handler(request: Request, exc: SiloError) -> Response:
    headers: dict[str, str] = {}
    if isinstance(exc, RateLimited) and exc.retry_after is not None:
        headers["Retry-After"] = str(exc.retry_after)

    if not _is_api(request):
        # An HTML error page for pages. A lost session sends the visitor to /login.
        if isinstance(exc, InvalidToken):
            return _login_redirect(request)
        return _error_page(request, exc.status_code, exc.detail, headers)

    body: dict = {"detail": exc.detail, "code": exc.code}
    if isinstance(exc, InvalidToken):
        headers["WWW-Authenticate"] = "Bearer"
    if isinstance(exc, ValidationFailed):
        body["errors"] = exc.errors
    return JSONResponse(body, status_code=exc.status_code, headers=headers)


async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    if _is_api(request):
        return await rate_limit_handler(request, exc)
    json_response = await rate_limit_handler(request, exc)
    headers = {"Retry-After": json_response.headers["Retry-After"]}
    if request.url.path.startswith("/s/"):
        headers |= PUBLIC_HEADERS  # the token is in this URL: keep it out of referrers and caches
    return _error_page(request, 429, RateLimited.detail, headers)


async def _validation_error_handler(request: Request, exc: RequestValidationError) -> Response:
    if not _is_api(request):
        return _error_page(request, 422, "Some of the submitted data is not valid.")
    # Never echo the input: it may contain a password.
    errors = [
        {"field": str(err["loc"][-1]) if err["loc"] else "", "message": err["msg"]}
        for err in exc.errors()
    ]
    body = {"detail": "Validation error.", "code": "validation_error", "errors": errors}
    return JSONResponse(body, status_code=422)


async def _http_error_handler(request: Request, exc: StarletteHTTPException) -> Response:
    if not _is_api(request) and request.url.path not in {"/healthz", "/readyz", "/metrics"}:
        message = _PAGE_MESSAGES.get(exc.status_code, str(exc.detail))
        return _error_page(request, exc.status_code, message, exc.headers)
    code = _HTTP_CODES.get(exc.status_code, "http_error")
    return JSONResponse(
        {"detail": str(exc.detail), "code": code},
        status_code=exc.status_code,
        headers=exc.headers,
    )


async def _unhandled_error_handler(request: Request, exc: Exception) -> Response:
    logger.exception("Unhandled error")
    if not _is_api(request):
        return _error_page(request, 500, "Something went wrong. Please try again later.")
    return JSONResponse(
        {"detail": "Internal server error.", "code": "internal_error"}, status_code=500
    )


def create_app(
    settings: Settings | None = None,
    blob_store: BlobStore | None = None,
    *,
    initial_admin: bool = True,
) -> FastAPI:
    """Build the FastAPI application.

    Args:
        settings: configuration; read from the environment when omitted (the normal case with
            ``uvicorn --factory``, where an invalid configuration stops the startup).
        blob_store: a ready BlobStore, used by tests to inject a fake. When omitted, the
            lifespan creates the Azure store (``create_blob_store``), which a bad connection
            string stops at startup.
        initial_admin: create the first admin at startup (always True in production). Tests that
            run without a database pass False.
    """
    configure_logging()
    settings = settings or get_settings()
    docs = settings.enable_docs  # docs only in local and dev
    app = FastAPI(
        title="Silo",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings
    app.state.blob_store = blob_store
    app.state.initial_admin = initial_admin
    # Routes read settings through get_settings(); make them see the injected object.
    app.dependency_overrides[get_settings] = lambda: settings

    # A new app starts with empty rate limit counters (matters for tests; one app per process
    # in production).
    reset_limits()
    app.state.limiter = limiter

    # Added first = innermost, so BaseHTTPMiddleware does not wrap its 413 (see its docstring).
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(AuthCookieMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)  # outermost: also covers error pages and 413
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
    app.add_exception_handler(SiloError, _silo_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)
    # Bootstrap is served from here, so the CSP can stay `style-src 'self'`.
    app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
    app.include_router(health.router)
    app.include_router(api_router)
    app.include_router(public.router)
    app.include_router(pages.router)
    app.include_router(team_pages.router)
    app.include_router(file_pages.router)
    app.include_router(admin_pages.router)
    return app
