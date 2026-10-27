"""Page infrastructure: cookies, CSRF, Origin checks, error pages.

Tests without the ``db`` marker never reach the database (no valid cookie is involved).
"""

import uuid
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request, Response

from app.config import Settings
from app.errors import CsrfFailed, InvalidToken, RefreshInProgress
from app.middleware import (
    check_origin,
    cookie_names,
    mark_logged_in,
    mark_logged_out,
    safe_next,
    set_auth_cookies,
    set_csrf_cookie,
)
from app.models import Role
from app.routers import admin_pages, file_pages, pages, team_pages
from app.routers.common import (
    PRE_SESSION_BINDING,
    CsrfChecked,
    PageUser,
    require_csrf,
    verify_origin,
)
from app.security import create_access_token, create_csrf_token
from app.services import sessions
from app.services.sessions import IssuedTokens
from tests.conftest import ORIGIN, UserFactory, make_settings, route_calls, token_of

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


@pytest.mark.parametrize("path", ["/_private", "/account", "/teams", "/files"])
async def test_unauthenticated_page_redirects_to_login_with_next(
    client: httpx.AsyncClient, page_routes: FastAPI, path: str
) -> None:
    """A page that needs a login sends visitors to /login and remembers where they were."""
    response = await client.get(path, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/login?next={path}"


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
    """Pages accept cookies only (section 7): a token in the Authorization header is not read.

    If it were read, the lookup would reach the (absent) database and fail with a 500 instead of
    this redirect.
    """
    token = create_access_token(
        user_id=1,
        session_id=uuid.uuid4(),
        secret=settings.jwt_secret.get_secret_value(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl=timedelta(minutes=15),
    )
    response = await client.get(
        "/files", headers={"Authorization": f"Bearer {token}"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_templates_have_no_inline_script_or_style() -> None:
    """The CSP allows only 'self' scripts and styles: scripts must be files from /static/."""
    for path in TEMPLATES.glob("*.html"):
        text = path.read_text().lower().replace("<script src=\"{{ url_for('static'", "")
        for forbidden in ("<script", "<style", " style=", "onclick=", "javascript:"):
            assert forbidden not in text, f"{path.name}: {forbidden}"


def test_pages_load_forms_js_and_the_upload_form_feeds_it() -> None:
    """Every page loads forms.js; the upload form gives it the size limit and a message box.

    The script itself cannot run here, so this only guards the contract between page and script.
    """
    assert "static', path='forms.js'" in (TEMPLATES / "base.html").read_text()
    files_page = (TEMPLATES / "files.html").read_text()
    script = (TEMPLATES.parent / "static" / "forms.js").read_text()
    for name in ("data-max-bytes", "data-max-label", 'id="upload-error"'):
        assert name in files_page
    for name in ("maxBytes", "maxLabel", "upload-error"):
        assert name in script


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
        ("/\\evil.example", "/files"),
        ("https://evil.example", "/files"),
        ("http://evil.example/files", "/files"),
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
    checked inside the route, and the route must at least depend on the Origin check.
    """
    checked, unprotected = 0, []
    for router in (pages.router, team_pages.router, file_pages.router, admin_pages.router):
        for route in router.routes:
            if route.methods - {"GET", "HEAD", "OPTIONS"}:
                checked += 1
                calls = route_calls(route.dependant)
                if route.path == "/files/upload":
                    assert verify_origin in calls
                elif require_csrf not in calls:
                    unprotected.append(f"{sorted(route.methods)} {route.path}")
    assert checked > 20, "the test no longer finds the routes"
    assert unprotected == []


@pytest.mark.parametrize("case", ["no cookie", "no field", "neither", "different pair", "forged"])
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
    elif case == "neither":
        cookies, field = {}, {}
    elif case == "different pair":
        field = {"csrf_token": csrf_pair(settings)[0]}  # valid, but not the cookie's token
    else:  # forged: a matching pair that was not signed with CSRF_SECRET
        forged = create_csrf_token("f" * 40, PRE_SESSION_BINDING)
        cookies = cookie_header(**{cookie_names(settings).csrf: forged})
        field = {"csrf_token": forged}
    response = await client.post("/_form", data=field, headers={**cookies, **ORIGIN})
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
            {"Origin": "http://testserver", "Sec-Fetch-Site": "cross-site"}, 403, id="cross-site"
        ),
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


async def test_a_csrf_cookie_for_another_binding_is_replaced(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    """A token bound to some session is not reused on an anonymous page: a new one is set."""
    token, cookies = csrf_pair(settings, binding=str(uuid.uuid4()))
    response = await client.get("/login", headers=cookies)
    new_token = token_of(response)
    assert new_token != token
    assert csrf_set_cookies(response, settings)[0].startswith(
        f"{cookie_names(settings).csrf}={new_token}"
    )


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


async def test_login_wins_over_dead_cookies_marked_for_deletion(
    client: httpx.AsyncClient, app: FastAPI, settings: Settings
) -> None:
    """Dead cookies seen by the CSRF check, then a login in the same request: the new cookies stay.

    Before ``mark_logged_in`` the login route set the cookies and the middleware deleted them
    again afterwards, so the user landed on /login after a successful login.
    """

    @app.get("/_dead_cookies_then_login")
    async def _dead_cookies_then_login(request: Request) -> Response:
        request.state.clear_auth_cookies = True  # what the page dependency leaves for dead cookies
        mark_logged_in(request, tokens())
        return Response()

    response = await client.get("/_dead_cookies_then_login")
    names = cookie_names(settings)
    lines = set_cookie_lines(response)
    for name, value in ((names.access, "access-value"), (names.refresh, "refresh-value")):
        written = [line for line in lines if line.startswith(f"{name}=")]
        assert len(written) == 1 and written[0].startswith(f"{name}={value}"), written
        assert "Max-Age=0" not in written[0]


@pytest.mark.parametrize(("error", "deleted"), [(RefreshInProgress, False), (InvalidToken, True)])
@pytest.mark.parametrize("path", ["/login", "/account"])
async def test_cookies_survive_a_refresh_running_in_parallel(
    client: httpx.AsyncClient,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    error: type[Exception],
    deleted: bool,
    path: str,
) -> None:
    """A lost refresh race keeps the cookies; an ended session deletes them.

    Two page requests with an expired access cookie: one rotates the refresh token, the other
    gets RefreshInProgress. The second must not delete the cookies, or the browser could drop
    the new tokens of the first and the user would be logged out. ``/login`` is an optional
    login page, ``/account`` needs a login and redirects.
    """

    async def rotate(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(sessions, "rotate_refresh", rotate)
    names = cookie_names(settings)
    response = await client.get(
        path, headers=cookie_header(**{names.refresh: "some-token"}), follow_redirects=False
    )
    cleared = [line for line in set_cookie_lines(response) if "Max-Age=0" in line]
    assert bool(cleared) is deleted


# --- Needs PostgreSQL ------------------------------------------------------------------------


async def start_session(db_sessionmaker, settings: Settings, user_factory: UserFactory):
    user = await user_factory(username="anna")
    async with db_sessionmaker() as db, db.begin():
        return user, await sessions.create_session(db, settings, user)


@pytest.mark.db
async def test_valid_access_cookie_logs_in_without_changing_cookies(
    client: httpx.AsyncClient,
    page_routes: FastAPI,
    settings: Settings,
    db_sessionmaker,
    user_factory: UserFactory,
) -> None:
    """A valid access cookie identifies the user; nothing is refreshed or set."""
    _, issued = await start_session(db_sessionmaker, settings, user_factory)
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
    _, issued = await start_session(db_sessionmaker, settings, user_factory)
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
async def test_revoked_session_redirects_and_clears_cookies(
    client: httpx.AsyncClient,
    page_routes: FastAPI,
    settings: Settings,
    db_sessionmaker,
    user_factory: UserFactory,
) -> None:
    """After logout the same cookies lead to /login, and both are deleted."""
    user, issued = await start_session(db_sessionmaker, settings, user_factory)
    async with db_sessionmaker() as db, db.begin():
        await sessions.revoke(db, user.id, issued.session_id)
    names = cookie_names(settings)
    response = await client.get(
        "/_private",
        headers=cookie_header(
            **{names.access: issued.access_token, names.refresh: issued.refresh_token}
        ),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")
    cleared = {line.split("=")[0] for line in set_cookie_lines(response) if "Max-Age=0" in line}
    assert cleared == {names.access, names.refresh}


@pytest.mark.db
async def test_csrf_token_is_bound_to_the_session(
    client: httpx.AsyncClient,
    page_routes: FastAPI,
    settings: Settings,
    db_sessionmaker,
    user_factory: UserFactory,
) -> None:
    """For a logged-in user only a token of their own session works."""
    _, issued = await start_session(db_sessionmaker, settings, user_factory)
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
