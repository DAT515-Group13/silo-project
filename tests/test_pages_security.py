"""Web security: response headers, cookies, CSRF, Origin checks, error pages.

Tests without the ``db`` marker never reach the database (no valid cookie is involved).
"""

import json
import logging
import re
import sys
import uuid
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request, Response

from app.config import Settings
from app.errors import CsrfFailed, InvalidToken, RefreshInProgress
from app.main import JsonFormatter
from app.middleware import (
    SECURITY_HEADERS,
    check_origin,
    cookie_names,
    mark_logged_out,
    safe_next,
    set_auth_cookies,
    set_csrf_cookie,
)
from app.models import Role
from app.routers import admin_pages, file_pages, pages, team_pages
from app.routers.common import (
    PRE_SESSION_BINDING,
    AuditCtx,
    CsrfChecked,
    PageUser,
    require_csrf,
)
from app.security import create_csrf_token
from app.services import sessions
from app.services.sessions import IssuedTokens
from tests.conftest import (
    ORIGIN,
    ActAs,
    UserFactory,
    assert_secure,
    bearer,
    issue_session,
    make_settings,
    route_calls,
    token_for,
    token_of,
)

pytestmark = pytest.mark.anyio

TEMPLATES = Path(__file__).resolve().parent.parent / "app" / "templates"


@pytest.fixture
def page_routes(app: FastAPI) -> FastAPI:
    """Add one protected page and one CSRF-protected POST to the app."""

    @app.get("/_private")
    async def _private(user: PageUser) -> dict[str, str]:
        return {"username": user.username}

    @app.post("/_form", dependencies=[CsrfChecked])
    async def _form() -> dict[str, bool]:
        return {"ok": True}

    return app


def cookie_header(**cookies: str) -> dict[str, str]:
    """A Cookie header (set by hand: it works the same for every host name)."""
    return {"Cookie": "; ".join(f"{name}={value}" for name, value in cookies.items())}


def csrf_pair(settings: Settings, binding: str = PRE_SESSION_BINDING) -> tuple[str, dict]:
    """A CSRF token with the cookie header that carries it, and the form data."""
    token = create_csrf_token(settings.csrf_secret.get_secret_value(), binding)
    return token, cookie_header(**{cookie_names(settings).csrf: token})


def set_cookie_lines(response: httpx.Response) -> list[str]:
    return response.headers.get_list("set-cookie")


# --- Static files and error pages ------------------------------------------------------------


@pytest.mark.parametrize("path", ["/login", "/healthz", "/api/v1/me", "/no-such-page"])
async def test_every_response_has_the_headers_and_is_not_cached(
    client: httpx.AsyncClient, path: str
) -> None:
    """Pages, API answers, errors and probes all carry the headers and Cache-Control: no-store.

    Each also gets a new ``X-Request-ID`` (32 hex characters); one sent by the client is ignored.
    """
    response = await client.get(path, headers={"X-Request-ID": "chosen-by-client"})
    assert_secure(response)
    assert response.headers["cache-control"] == "no-store"
    request_id = response.headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f]{32}", request_id)
    assert (await client.get(path)).headers["x-request-id"] != request_id


def test_security_headers_have_the_exact_values() -> None:
    """Written out here: ``assert_secure`` reads the constant, so it cannot see a weaker value."""
    assert SECURITY_HEADERS == {
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }


async def test_request_id_reaches_the_audit_context(
    client: httpx.AsyncClient, app: FastAPI, act_as: ActAs
) -> None:
    """The audit row of a request gets the ID of its response header."""

    @app.get("/_audit_id")
    async def _audit_id(ctx: AuditCtx) -> dict[str, str | None]:
        return {"request_id": ctx.request_id}

    act_as(Role.user)
    response = await client.get("/_audit_id")
    assert response.json() == {"request_id": response.headers["x-request-id"]}


@pytest.mark.parametrize("path", ["/_boom", "/api/v1/_boom"])
async def test_a_crash_is_logged_with_the_request_id_of_its_500(
    client: httpx.AsyncClient, app: FastAPI, caplog: pytest.LogCaptureFixture, path: str
) -> None:
    """The last-resort 500 (page and API) carries the ID, and so does the logged stack trace.

    The answer stays generic: nothing of the exception reaches the client.
    """

    async def boom() -> None:
        raise RuntimeError("internal detail")

    app.add_api_route(path, boom)
    with caplog.at_level(logging.ERROR, logger="silo"):
        response = await client.get(path)
    assert response.status_code == 500
    assert "internal detail" not in response.text and "Traceback" not in response.text
    if path.startswith("/api/"):
        assert response.json() == {"detail": "Internal server error.", "code": "internal_error"}
    request_id = response.headers["x-request-id"]
    record = next(r for r in caplog.records if r.getMessage() == "Unhandled error")
    record.request_id = request_id  # set by the handler's AddRequestId filter in production
    assert json.loads(JsonFormatter().format(record))["request_id"] == request_id


async def test_static_files_stay_cacheable_but_get_the_other_headers(
    client: httpx.AsyncClient,
) -> None:
    """Bootstrap is served from /static (so the CSP can stay 'self') and may be cached."""
    response = await client.get("/static/bootstrap.min.css")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert "Bootstrap" in response.text[:200]
    assert response.headers.get("cache-control") != "no-store"
    assert_secure(response)


async def test_page_errors_are_html_and_api_errors_are_json(client: httpx.AsyncClient) -> None:
    """Under /api/ errors are JSON, elsewhere an HTML page without internals."""
    page = await client.get("/no-such-page")
    assert page.status_code == 404
    assert page.headers["content-type"].startswith("text/html")
    assert "Page not found." in page.text
    assert "Traceback" not in page.text

    api = await client.get("/api/v1/no-such-endpoint")
    assert api.status_code == 404
    assert api.json() == {"detail": "Not Found", "code": "not_found"}

    wrong_method = await client.delete("/api/v1/auth/login")
    assert wrong_method.status_code == 405
    assert wrong_method.json()["code"] == "method_not_allowed"


@pytest.mark.parametrize("path", ["/account", "/teams", "/files", "/links"])
async def test_unauthenticated_page_redirects_to_login_with_next(
    client: httpx.AsyncClient, path: str
) -> None:
    """A page that needs a login sends visitors to /login and remembers where they were."""
    response = await client.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/login?next={path}"


async def test_start_page_sends_visitors_to_login_and_users_to_files(
    client: httpx.AsyncClient, act_as: ActAs
) -> None:
    """``/`` has no content of its own: it only redirects."""
    anonymous = await client.get("/", follow_redirects=False)
    assert (anonymous.status_code, anonymous.headers["location"]) == (303, "/login")
    act_as(Role.user)
    logged_in = await client.get("/", follow_redirects=False)
    assert (logged_in.status_code, logged_in.headers["location"]) == (303, "/files")


async def test_useless_cookies_are_deleted_on_the_redirect(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings
) -> None:
    """Garbage cookies are not kept: the redirect to /login deletes them."""
    names = cookie_names(settings)
    response = await client.get(
        "/_private",
        headers=cookie_header(**{names.access: "garbage"}),
        follow_redirects=False,
    )
    assert response.status_code == 303
    deleted = [line for line in set_cookie_lines(response) if line.startswith(names.access)]
    assert deleted and "Max-Age=0" in deleted[0]


async def test_bearer_header_is_ignored_on_pages(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    """Pages accept cookies only: a token in the Authorization header is not read.

    If it were read, the lookup would reach the (absent) database and fail with a 500 instead of
    this redirect.
    """
    token = token_for(settings, 1, uuid.uuid4())
    response = await client.get("/files", headers=bearer(token), follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_templates_have_no_inline_script_or_style() -> None:
    """The CSP allows only 'self' scripts and styles: scripts must be files from /static/.

    The ``safe`` filter is forbidden too: it would switch off the escaping of stored names.
    """
    templates = list(TEMPLATES.glob("*.html"))
    assert templates  # the guard must not pass because the glob found nothing
    for path in templates:
        text = path.read_text().lower().replace("<script src=\"{{ url_for('static'", "")
        for forbidden in (
            "<script",
            "<style",
            " style=",
            "onclick=",
            "javascript:",
            "|safe",
            "| safe",
        ):
            assert forbidden not in text, f"{path.name}: {forbidden}"


def test_static_scripts_never_write_html() -> None:
    """Our own scripts only set text, so a file name or message can never become markup."""
    scripts = list(TEMPLATES.parent.glob("static/*.js"))
    assert scripts  # the guard must not pass because the glob found nothing
    for path in scripts:
        text = path.read_text()
        for forbidden in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "eval(",
            "document.write",
        ):
            assert forbidden not in text, f"{path.name}: {forbidden}"


# --- Cookies ---------------------------------------------------------------------------------


def tokens() -> IssuedTokens:
    return IssuedTokens("access-value", "refresh-value", 900, 604800, None, 1, "anna", Role.user)  # type: ignore[arg-type]


def test_cookie_flags_in_production_settings() -> None:
    """__Host- names, HttpOnly, Secure, Path=/, no Domain; Lax for access, Strict for refresh."""
    settings = make_settings(cookie_secure=True)
    response = Response()
    set_auth_cookies(response, settings, tokens())
    set_csrf_cookie(response, settings, "csrf-value")
    lines = {line.split("=")[0]: line for line in response.headers.getlist("set-cookie")}

    assert set(lines) == {"__Host-access_token", "__Host-refresh_token", "__Host-csrf_token"}
    for line in lines.values():
        assert "HttpOnly" in line and "Secure" in line and "Path=/" in line
        assert "Domain" not in line
    assert "SameSite=lax" in lines["__Host-access_token"]
    assert "SameSite=strict" in lines["__Host-refresh_token"]
    assert "SameSite=strict" in lines["__Host-csrf_token"]
    assert "Max-Age=900" in lines["__Host-access_token"]
    assert "Max-Age=604800" in lines["__Host-refresh_token"]


def test_cookie_names_without_secure_drop_the_host_prefix() -> None:
    """With COOKIE_SECURE=false (local only) the __Host- prefix and Secure are dropped."""
    settings = make_settings(cookie_secure=False)
    assert cookie_names(settings).access == "access_token"
    response = Response()
    set_auth_cookies(response, settings, tokens())
    line = response.headers.getlist("set-cookie")[0]
    assert line.startswith("access_token=") and "Secure" not in line


# --- next parameter --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/files", "/files"),
        ("/files/abc?tab=shared", "/files/abc?tab=shared"),
        ("/", "/"),
        (None, "/files"),
        ("", "/files"),
        ("files", "/files"),
        ("//evil.example", "/files"),
        ("///evil.example", "/files"),  # browsers read extra slashes like //
        ("/\\evil.example", "/files"),
        ("https://evil.example", "/files"),
        ("javascript:alert(1)", "/files"),
        ("/ok\r\nSet-Cookie: x=1", "/files"),
    ],
)
def test_safe_next(value: str | None, expected: str) -> None:
    """Only a relative path with a single leading slash survives."""
    assert safe_next(value) == expected


# --- CSRF ------------------------------------------------------------------------------------


def test_every_page_post_checks_csrf() -> None:
    """No state-changing page route may forget ``CsrfChecked``.

    The one exception is the streaming upload: its token is the first multipart part, so it is
    checked inside the route (``test_upload_needs_the_csrf_token_first``).
    """
    checked, unprotected = 0, []
    for router in (pages.router, team_pages.router, file_pages.router, admin_pages.router):
        for route in router.routes:
            if route.methods - {"GET", "HEAD", "OPTIONS"}:
                checked += 1
                calls = route_calls(route.dependant)
                if route.path != "/files/upload" and require_csrf not in calls:
                    unprotected.append(f"{sorted(route.methods)} {route.path}")
    assert checked > 20, "the test no longer finds the routes"
    assert unprotected == []


@pytest.mark.parametrize("case", ["no cookie", "no field", "different pair", "forged"])
async def test_bad_csrf_token_is_403(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings, case: str
) -> None:
    """Double submit: both places must hold the same token, signed with CSRF_SECRET."""
    token, cookies = csrf_pair(settings)
    field: dict[str, str] = {"csrf_token": token}
    if case == "no cookie":
        cookies = {}
    elif case == "no field":
        field = {}
    elif case == "different pair":
        field = {"csrf_token": csrf_pair(settings)[0]}  # valid, but not the cookie's token
    else:  # forged: a matching pair that was not signed with CSRF_SECRET
        forged = create_csrf_token("f" * 40, PRE_SESSION_BINDING)
        cookies = cookie_header(**{cookie_names(settings).csrf: forged})
        field = {"csrf_token": forged}
    response = await client.post("/_form", data=field, headers={**cookies, **ORIGIN})
    assert response.status_code == 403
    assert "CSRF validation failed." in response.text


async def test_page_form_must_be_urlencoded(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings
) -> None:
    """A multipart body is refused even with a valid token: it could spool files to the disk."""
    token, cookies = csrf_pair(settings)
    response = await client.post(
        "/_form", files={"csrf_token": (None, token)}, headers={**cookies, **ORIGIN}
    )
    assert response.status_code == 403
    assert "CSRF validation failed." in response.text


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        pytest.param(ORIGIN, 200, id="origin matches"),
        pytest.param({"Referer": "http://testserver/login"}, 200, id="referer instead of origin"),
        pytest.param(
            {"Origin": "http://TESTSERVER", "Sec-Fetch-Site": "same-origin"},
            200,
            id="same-origin fetch metadata",
        ),
        pytest.param({"Origin": "http://evil.example"}, 403, id="foreign origin"),
        pytest.param({"Origin": "null"}, 403, id="null origin"),
        pytest.param({"Origin": "https://testserver"}, 403, id="wrong scheme"),
        pytest.param({"Referer": "http://evil.example/page"}, 403, id="foreign referer"),
        pytest.param({}, 403, id="neither origin nor referer"),
        pytest.param(
            {"Origin": "http://testserver", "Sec-Fetch-Site": "same-site"}, 403, id="same-site"
        ),
    ],
)
async def test_post_is_accepted_only_from_this_site(
    client: httpx.AsyncClient,
    page_routes: FastAPI,
    settings: Settings,
    headers: dict,
    expected: int,
) -> None:
    """A valid token is accepted only with an Origin or Referer of this site (else 403)."""
    token, cookies = csrf_pair(settings)
    response = await client.post(
        "/_form", data={"csrf_token": token}, headers={**cookies, **headers}
    )
    assert response.status_code == expected


def csrf_set_cookies(response: httpx.Response, settings: Settings) -> list[str]:
    """The Set-Cookie lines of a response that write the CSRF cookie."""
    name = cookie_names(settings).csrf
    return [line for line in set_cookie_lines(response) if line.startswith(f"{name}=")]


async def test_a_form_still_works_after_another_tab_loaded_a_page(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings
) -> None:
    """Two open tabs: a valid CSRF cookie is reused, so the first tab's form still works."""
    first_tab = await client.get("/login")
    second_tab = await client.get("/login")
    first_token = token_of(first_tab)
    assert token_of(second_tab) == first_token
    assert csrf_set_cookies(second_tab, settings) == []
    response = await client.post("/_form", data={"csrf_token": first_token}, headers=ORIGIN)
    assert response.status_code == 200


async def test_logout_wins_over_cookies_refreshed_in_the_same_request(
    client: httpx.AsyncClient, app: FastAPI, settings: Settings
) -> None:
    """A session refreshed and then ended in one request leaves no auth cookies behind."""

    @app.get("/_refresh_then_logout")
    async def _refresh_then_logout(request: Request) -> Response:
        request.state.refreshed_tokens = tokens()  # what the page dependency would leave
        mark_logged_out(request)
        return Response()

    response = await client.get("/_refresh_then_logout")
    names = cookie_names(settings)
    lines = set_cookie_lines(response)
    for name in (names.access, names.refresh):
        written = [line for line in lines if line.startswith(f"{name}=")]
        assert len(written) == 1 and "Max-Age=0" in written[0]
    assert not any("access-value" in line or "refresh-value" in line for line in lines)


@pytest.mark.parametrize(("error", "deleted"), [(RefreshInProgress, False), (InvalidToken, True)])
async def test_cookies_survive_a_refresh_running_in_parallel(
    client: httpx.AsyncClient,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    error: type[Exception],
    deleted: bool,
) -> None:
    """A lost refresh race keeps the cookies; an ended session deletes them.

    Two page requests with an expired access cookie: one rotates the refresh token, the other
    gets RefreshInProgress. The second must not delete the cookies, or the browser could drop
    the new tokens of the first and the user would be logged out.
    """

    async def rotate(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(sessions, "rotate_refresh", rotate)
    names = cookie_names(settings)
    response = await client.get(
        "/account", headers=cookie_header(**{names.refresh: "some-token"}), follow_redirects=False
    )
    cleared = [line for line in set_cookie_lines(response) if "Max-Age=0" in line]
    assert bool(cleared) is deleted


# --- Needs PostgreSQL ------------------------------------------------------------------------


@pytest.mark.db
async def test_valid_access_cookie_logs_in_without_changing_cookies(
    client: httpx.AsyncClient,
    page_routes: FastAPI,
    settings: Settings,
    db_sessionmaker,
    user_factory: UserFactory,
) -> None:
    """A valid access cookie identifies the user; nothing is refreshed or set."""
    issued = await issue_session(db_sessionmaker, settings, await user_factory(username="anna"))
    names = cookie_names(settings)
    response = await client.get(
        "/_private", headers=cookie_header(**{names.access: issued.access_token})
    )
    assert response.status_code == 200
    assert response.json() == {"username": "anna"}
    assert set_cookie_lines(response) == []


@pytest.mark.db
async def test_expired_access_cookie_is_refreshed_transparently(
    client: httpx.AsyncClient,
    page_routes: FastAPI,
    settings: Settings,
    db_sessionmaker,
    user_factory: UserFactory,
) -> None:
    """Only the refresh cookie is left: the request succeeds and new cookies are set."""
    issued = await issue_session(db_sessionmaker, settings, await user_factory(username="anna"))
    names = cookie_names(settings)

    response = await client.get(
        "/_private", headers=cookie_header(**{names.refresh: issued.refresh_token})
    )
    assert response.status_code == 200
    lines = set_cookie_lines(response)
    assert {line.split("=")[0] for line in lines} == {names.access, names.refresh}
    new_refresh = next(line for line in lines if line.startswith(names.refresh))
    assert issued.refresh_token not in new_refresh

    # The new access cookie works on its own for the next request.
    new_access = next(line for line in lines if line.startswith(names.access))
    value = new_access.split(";")[0].split("=", 1)[1]
    again = await client.get("/_private", headers=cookie_header(**{names.access: value}))
    assert again.status_code == 200


@pytest.mark.db
async def test_csrf_token_is_bound_to_the_session(
    client: httpx.AsyncClient,
    page_routes: FastAPI,
    settings: Settings,
    db_sessionmaker,
    user_factory: UserFactory,
) -> None:
    """For a logged-in user only a token of their own session works."""
    issued = await issue_session(db_sessionmaker, settings, await user_factory(username="anna"))
    names = cookie_names(settings)

    async def post(binding: str) -> int:
        token, _ = csrf_pair(settings, binding)
        headers = cookie_header(**{names.access: issued.access_token, names.csrf: token})
        response = await client.post(
            "/_form", data={"csrf_token": token}, headers={**headers, **ORIGIN}
        )
        return response.status_code

    assert await post(str(issued.session_id)) == 200
    assert await post(PRE_SESSION_BINDING) == 403
    assert await post(str(uuid.uuid4())) == 403  # a token of some other session


@pytest.mark.parametrize(
    ("base_url", "sender", "allowed"),
    [
        ("https://silo.example", "https://silo.example:443", True),
        ("https://silo.example:443", "https://silo.example", True),
        ("http://localhost:8000", "http://localhost:8000", True),
        ("https://silo.example", "http://silo.example", False),
        ("http://localhost:8000", "http://localhost:8001", False),
        ("https://silo.example", "https://silo.example:bad", False),
    ],
)
def test_origin_comparison_ignores_default_ports(base_url: str, sender: str, allowed: bool) -> None:
    """The browser sends `https://x`, an operator may write `https://x:443`: same origin."""
    request = Request({"type": "http", "headers": [(b"origin", sender.encode())]})
    settings = make_settings(base_url=base_url, cookie_secure=base_url.startswith("https"))
    if allowed:
        check_origin(request, settings)
    else:
        with pytest.raises(CsrfFailed):
            check_origin(request, settings)


def test_a_log_record_is_one_line_of_json() -> None:
    """A line break in a message cannot start a second log line, and a stack trace stays inside."""
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord(
            "silo", logging.ERROR, __file__, 1, "bad\nINFO fake line", None, sys.exc_info()
        )
    record.request_id = "abc"
    line = JsonFormatter().format(record)
    assert "\n" not in line
    entry = json.loads(line)
    assert entry["message"] == "bad\nINFO fake line"
    assert entry["level"] == "ERROR" and entry["request_id"] == "abc"
    assert "ValueError: boom" in entry["exception"]
