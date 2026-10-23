"""Page infrastructure: cookies, CSRF, Origin checks, error pages.

Tests without the ``db`` marker never reach the database (no valid cookie is involved).
"""

import re
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, Request, Response

from app.config import Settings
from app.errors import InvalidToken, RefreshInProgress
from app.middleware import (
    cookie_names,
    mark_logged_out,
    safe_next,
    set_auth_cookies,
    set_csrf_cookie,
)
from app.models import Role
from app.routers.common import PRE_SESSION_BINDING, CsrfChecked, PageUser, templates
from app.security import create_csrf_token
from app.services import sessions
from app.services.sessions import IssuedTokens
from tests.conftest import UserFactory, make_settings

pytestmark = pytest.mark.anyio

ORIGIN = {"Origin": "http://testserver"}
TOKEN_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')
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


async def test_bootstrap_is_served_locally(client: httpx.AsyncClient) -> None:
    """Bootstrap comes from /static, so the CSP can stay 'self'."""
    response = await client.get("/static/bootstrap.min.css")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert "Bootstrap  v5.3.3" in response.text[:200]


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


async def test_unauthenticated_page_redirects_to_login_with_next(
    client: httpx.AsyncClient, page_routes: FastAPI
) -> None:
    """A page that needs a login sends visitors to /login and remembers where they were."""
    response = await client.get("/_private", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/_private"


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


def test_templates_have_no_inline_script_or_style() -> None:
    """The CSP allows only 'self' scripts and styles."""
    for path in TEMPLATES.glob("*.html"):
        text = path.read_text().lower()
        for forbidden in ("<script", "<style", " style=", "onclick=", "javascript:"):
            assert forbidden not in text, f"{path.name}: {forbidden}"


def test_templates_escape_user_data() -> None:
    """Autoescaping is on: a username with HTML is shown as text."""
    user = SimpleNamespace(username="<img src=x onerror=alert(1)>", role=Role.user)
    html = templates.get_template("base.html").render(
        user=user, csrf_token="t", url_for=lambda *args, **kwargs: "/static/x.css"
    )
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


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


async def test_post_with_a_valid_token_and_origin_works(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings
) -> None:
    """Cookie, form field and Origin all agree: the POST is accepted (pre-session token)."""
    token, cookies = csrf_pair(settings)
    response = await client.post(
        "/_form", data={"csrf_token": token}, headers={**cookies, **ORIGIN}
    )
    assert response.status_code == 200


async def test_post_without_a_token_is_403(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings
) -> None:
    """No token at all: csrf_failed."""
    response = await client.post("/_form", data={"x": "1"}, headers=ORIGIN)
    assert response.status_code == 403
    assert "CSRF validation failed." in response.text


@pytest.mark.parametrize("missing", ["cookie", "field"])
async def test_post_needs_both_cookie_and_field(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings, missing: str
) -> None:
    """Double submit: a token in only one of the two places is refused."""
    token, cookies = csrf_pair(settings)
    response = await client.post(
        "/_form",
        data={} if missing == "field" else {"csrf_token": token},
        headers={**(cookies if missing == "field" else {}), **ORIGIN},
    )
    assert response.status_code == 403


async def test_post_with_different_cookie_and_field_is_403(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings
) -> None:
    """Two valid tokens that are not the same one are refused (the pair must match)."""
    token_a, cookies = csrf_pair(settings)
    token_b, _ = csrf_pair(settings)
    response = await client.post(
        "/_form", data={"csrf_token": token_b}, headers={**cookies, **ORIGIN}
    )
    assert token_a != token_b
    assert response.status_code == 403


async def test_forged_token_is_403(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings
) -> None:
    """A matching pair that was not signed with CSRF_SECRET is refused."""
    forged = create_csrf_token("f" * 40, PRE_SESSION_BINDING)
    cookies = cookie_header(**{cookie_names(settings).csrf: forged})
    response = await client.post(
        "/_form", data={"csrf_token": forged}, headers={**cookies, **ORIGIN}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "http://evil.example"},
        {"Origin": "null"},
        {"Origin": "https://testserver"},  # wrong scheme
        {"Referer": "http://evil.example/page"},
        {},  # neither Origin nor Referer
        {"Origin": "http://testserver", "Sec-Fetch-Site": "cross-site"},
        {"Origin": "http://testserver", "Sec-Fetch-Site": "same-site"},
    ],
)
async def test_post_with_a_foreign_origin_is_403(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings, headers: dict
) -> None:
    """A correct token does not help when the request does not come from this site."""
    token, cookies = csrf_pair(settings)
    response = await client.post(
        "/_form", data={"csrf_token": token}, headers={**cookies, **headers}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "headers",
    [
        {"Referer": "http://testserver/login"},
        {"Origin": "http://TESTSERVER", "Sec-Fetch-Site": "same-origin"},
    ],
)
async def test_referer_and_same_origin_fetch_metadata_are_accepted(
    client: httpx.AsyncClient, page_routes: FastAPI, settings: Settings, headers: dict
) -> None:
    """Referer is accepted when Origin is absent; Sec-Fetch-Site same-origin is fine."""
    token, cookies = csrf_pair(settings)
    response = await client.post(
        "/_form", data={"csrf_token": token}, headers={**cookies, **headers}
    )
    assert response.status_code == 200


def csrf_set_cookies(response: httpx.Response, settings: Settings) -> list[str]:
    """The Set-Cookie lines of a response that write the CSRF cookie."""
    name = cookie_names(settings).csrf
    return [line for line in set_cookie_lines(response) if line.startswith(f"{name}=")]


async def test_a_valid_csrf_cookie_is_reused_by_the_next_page(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    """A page keeps the cookie's still-valid token instead of replacing it."""
    token, cookies = csrf_pair(settings)
    response = await client.get("/login", headers=cookies)
    assert TOKEN_FIELD.search(response.text).group(1) == token
    assert csrf_set_cookies(response, settings) == []


async def test_a_csrf_cookie_for_another_binding_is_replaced(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    """A token bound to some session is not reused on an anonymous page: a new one is set."""
    token, cookies = csrf_pair(settings, binding=str(uuid.uuid4()))
    response = await client.get("/login", headers=cookies)
    new_token = TOKEN_FIELD.search(response.text).group(1)
    assert new_token != token
    assert csrf_set_cookies(response, settings)[0].startswith(
        f"{cookie_names(settings).csrf}={new_token}"
    )


async def test_a_form_still_works_after_another_tab_loaded_a_page(
    client: httpx.AsyncClient, page_routes: FastAPI
) -> None:
    """Two open tabs: the first tab's form is still accepted after the second tab loaded."""
    first_tab = await client.get("/login")
    second_tab = await client.get("/login")
    first_token = TOKEN_FIELD.search(first_tab.text).group(1)
    assert TOKEN_FIELD.search(second_tab.text).group(1) == first_token
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
