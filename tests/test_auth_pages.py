"""Login, register, logout and account pages.

Tests without the ``db`` marker stay away from the database (no valid credentials involved).
The client keeps cookies between requests, like a browser.
"""

import re

import httpx
import pytest
from fastapi import FastAPI

from app.config import Settings, get_settings
from app.middleware import cookie_names
from app.models import UserStatus
from tests.conftest import TEST_PASSWORD, UserFactory, make_settings

pytestmark = pytest.mark.anyio

ORIGIN = {"Origin": "http://testserver"}
TOKEN_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')
GOOD_PASSWORD = "a-long-enough-password"


def token_of(response: httpx.Response) -> str:
    """The CSRF token a rendered form carries in its hidden field."""
    match = TOKEN_FIELD.search(response.text)
    assert match, "no csrf_token field in the page"
    return match.group(1)


async def post_form(
    client: httpx.AsyncClient, path: str, data: dict[str, str], *, token_from: str
) -> httpx.Response:
    """GET a page for a CSRF token, then POST the form to ``path`` like a browser would."""
    page = await client.get(token_from)
    return await client.post(
        path, data={**data, "csrf_token": token_of(page)}, headers=ORIGIN, follow_redirects=False
    )


def use_mode(app: FastAPI, settings: Settings, mode: str) -> None:
    changed = make_settings(
        database_url=settings.database_url.get_secret_value(), registration_mode=mode
    )
    app.dependency_overrides[get_settings] = lambda: changed


# --- No database needed ----------------------------------------------------------------------


async def test_login_page_has_a_form_with_a_csrf_token(
    client: httpx.AsyncClient, settings: Settings
) -> None:
    """The form asks for a username (no email), carries the token and sets the CSRF cookie."""
    response = await client.get("/login")
    assert response.status_code == 200
    assert 'name="username"' in response.text and 'autocomplete="username"' in response.text
    assert "email" not in response.text.lower()
    token = token_of(response)
    cookie = next(c for c in response.headers.get_list("set-cookie") if "csrf_token" in c)
    assert cookie.startswith(f"{cookie_names(settings).csrf}={token}")


async def test_login_page_sanitizes_next(client: httpx.AsyncClient) -> None:
    """An outside address in ?next= is replaced by /files (open redirect guard)."""
    for bad in ("//evil.example", "https://evil.example", "javascript:alert(1)"):
        response = await client.get("/login", params={"next": bad})
        assert 'name="next" value="/files"' in response.text
    response = await client.get("/login", params={"next": "/files/abc"})
    assert 'name="next" value="/files/abc"' in response.text


async def test_register_page_follows_the_registration_mode(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings
) -> None:
    """`closed` hides the registration page (404); the other modes show it."""
    assert (await client.get("/register")).status_code == 200
    use_mode(app, settings, "closed")
    assert (await client.get("/register")).status_code == 404
    use_mode(app, settings, "open")
    assert (await client.get("/register")).status_code == 200


async def test_account_page_needs_a_login(client: httpx.AsyncClient) -> None:
    """Without a session the account page redirects to /login and remembers the page."""
    response = await client.get("/account", follow_redirects=False)
    assert (response.status_code, response.headers["location"]) == (303, "/login?next=/account")


async def test_start_page_sends_visitors_to_login(client: httpx.AsyncClient) -> None:
    response = await client.get("/", follow_redirects=False)
    assert (response.status_code, response.headers["location"]) == (303, "/login")


async def test_login_post_without_csrf_is_403(client: httpx.AsyncClient) -> None:
    """A POST without a token, or with a token but no Origin, is refused."""
    body = {"username": "anna", "password": TEST_PASSWORD}
    assert (await client.post("/login", data=body, headers=ORIGIN)).status_code == 403
    page = await client.get("/login")
    with_token = {**body, "csrf_token": token_of(page)}
    assert (await client.post("/login", data=with_token)).status_code == 403
    assert (
        await client.post("/login", data=with_token, headers={"Origin": "http://evil.example"})
    ).status_code == 403


async def test_malformed_login_looks_like_a_wrong_password(client: httpx.AsyncClient) -> None:
    """A username that is too long is a plain failed login; the page never echoes the password."""
    response = await post_form(
        client,
        "/login",
        {"username": "x" * 80, "password": "secret-value-1234"},
        token_from="/login",
    )
    assert response.status_code == 401
    assert "Invalid username or password." in response.text
    assert "secret-value-1234" not in response.text


async def test_login_form_escapes_the_submitted_username(client: httpx.AsyncClient) -> None:
    """The username shown again after a failed login is HTML-escaped."""
    response = await post_form(
        client, "/login", {"username": "<b>x</b>" + "y" * 40, "password": "p"}, token_from="/login"
    )
    assert "<b>x</b>" not in response.text
    assert "&lt;b&gt;x&lt;/b&gt;" in response.text


async def test_register_form_validates_without_the_database(client: httpx.AsyncClient) -> None:
    """A bad username is reported on the form (422) and the password is not echoed."""
    response = await post_form(
        client,
        "/register",
        {"username": "x", "password": "secret-value-1234"},
        token_from="/register",
    )
    assert response.status_code == 422
    assert "Username must be 3-32 characters" in response.text
    assert "secret-value-1234" not in response.text


async def test_files_page_needs_a_login(client: httpx.AsyncClient) -> None:
    """The placeholder file list redirects to /login without a session, like the other pages."""
    response = await client.get("/files", follow_redirects=False)
    assert (response.status_code, response.headers["location"]) == (303, "/login?next=/files")


async def test_other_file_pages_are_still_skeletons(client: httpx.AsyncClient) -> None:
    """B's other file pages answer 501 as an HTML page until B implements them."""
    response = await client.get("/files/7f3a1c2e-5b9d-4e8a-9c41-2d6f0b8a1e33")
    assert response.status_code == 501
    assert response.headers["content-type"].startswith("text/html")


# --- Needs PostgreSQL ------------------------------------------------------------------------


@pytest.mark.db
async def test_register_approval_shows_the_same_page_for_new_and_taken_names(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """`approval` mode: one confirmation page, whether or not the username exists."""
    await user_factory(username="taken")
    pages = []
    for username in ("newcomer", "taken"):
        response = await post_form(
            client,
            "/register",
            {"username": username, "password": GOOD_PASSWORD},
            token_from="/register",
        )
        assert response.status_code == 200
        pages.append(re.sub(TOKEN_FIELD, "", response.text))
        assert "An admin must approve the account." in response.text
    assert pages[0].replace("newcomer", "") == pages[1].replace("taken", "")


@pytest.mark.db
async def test_register_open_redirects_to_login_and_the_account_works(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings
) -> None:
    """`open` mode: after registering you can log in with the new account."""
    use_mode(app, settings, "open")
    response = await post_form(
        client, "/register", {"username": "Anna", "password": GOOD_PASSWORD}, token_from="/register"
    )
    assert (response.status_code, response.headers["location"]) == (303, "/login?registered=1")
    login = await post_form(
        client, "/login", {"username": "anna", "password": GOOD_PASSWORD}, token_from="/login"
    )
    assert login.status_code == 303


@pytest.mark.db
async def test_login_sets_cookies_and_goes_to_next(
    client: httpx.AsyncClient, settings: Settings, user_factory: UserFactory
) -> None:
    """A correct login sets the access and refresh cookies and redirects to ?next= (checked)."""
    await user_factory(username="anna")
    names = cookie_names(settings)
    response = await post_form(
        client,
        "/login",
        {"username": "Anna", "password": TEST_PASSWORD, "next": "/account"},
        token_from="/login",
    )
    assert (response.status_code, response.headers["location"]) == (303, "/account")
    names_set = {c.split("=")[0] for c in response.headers.get_list("set-cookie")}
    assert {names.access, names.refresh} <= names_set

    account = await client.get("/account")
    assert account.status_code == 200
    assert "anna" in account.text and "this session" in account.text


@pytest.mark.db
async def test_files_placeholder_shows_the_storage_usage(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """After login the default target /files is a real page, not a 501 error."""
    await user_factory(username="anna")
    await post_form(
        client, "/login", {"username": "anna", "password": TEST_PASSWORD}, token_from="/login"
    )
    response = await client.get("/files")
    assert response.status_code == 200
    assert "not available yet" in response.text
    assert "0 Bytes of 1.1 GB" in response.text  # filesizeformat of 0 and the 1 GiB user quota


@pytest.mark.db
async def test_login_with_an_outside_next_goes_to_files(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """The open redirect guard also applies to the POST."""
    await user_factory(username="anna")
    response = await post_form(
        client,
        "/login",
        {"username": "anna", "password": TEST_PASSWORD, "next": "//evil.example"},
        token_from="/login",
    )
    assert response.headers["location"] == "/files"


@pytest.mark.db
async def test_failed_logins_show_the_same_message(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """Unknown user and wrong password: the same 401 form; pending accounts get a 403."""
    await user_factory(username="anna")
    await user_factory(username="waiting", status=UserStatus.pending)
    unknown = await post_form(
        client,
        "/login",
        {"username": "nobody", "password": "wrong-password-123"},
        token_from="/login",
    )
    wrong = await post_form(
        client,
        "/login",
        {"username": "anna", "password": "wrong-password-123"},
        token_from="/login",
    )
    pending = await post_form(
        client, "/login", {"username": "waiting", "password": TEST_PASSWORD}, token_from="/login"
    )
    assert unknown.status_code == wrong.status_code == 401
    assert "Invalid username or password." in unknown.text
    assert "Invalid username or password." in wrong.text
    assert pending.status_code == 403
    assert "pending approval" in pending.text


@pytest.mark.db
async def test_logout_ends_the_session_and_deletes_the_cookies(
    client: httpx.AsyncClient, settings: Settings, user_factory: UserFactory
) -> None:
    """POST /logout revokes the session, clears both cookies and the old cookie stops working."""
    await user_factory(username="anna")
    await post_form(
        client, "/login", {"username": "anna", "password": TEST_PASSWORD}, token_from="/login"
    )
    stale = dict(client.cookies)
    response = await post_form(client, "/logout", {}, token_from="/account")
    assert (response.status_code, response.headers["location"]) == (303, "/login")
    cleared = {c.split("=")[0] for c in response.headers.get_list("set-cookie") if "Max-Age=0" in c}
    names = cookie_names(settings)
    assert {names.access, names.refresh} <= cleared

    client.cookies.clear()
    for name, value in stale.items():
        client.cookies.set(name, value)
    assert (await client.get("/account", follow_redirects=False)).status_code == 303


@pytest.mark.db
async def test_account_page_can_sign_out_one_device_or_all(
    client: httpx.AsyncClient, settings: Settings, user_factory: UserFactory
) -> None:
    """Revoking another session keeps this one; logout-all ends everything and clears cookies."""
    await user_factory(username="anna")
    await post_form(
        client, "/login", {"username": "anna", "password": TEST_PASSWORD}, token_from="/login"
    )
    # A second device logs in through the API; its token tells us which session it is.
    other = (
        await client.post(
            "/api/v1/auth/login", json={"username": "anna", "password": TEST_PASSWORD}
        )
    ).json()
    listing = await client.get(
        "/api/v1/auth/sessions", headers={"Authorization": f"Bearer {other['access_token']}"}
    )
    other_id = next(row["id"] for row in listing.json() if row["current"])

    account = await client.get("/account")
    assert len(re.findall(r"/account/sessions/[0-9a-f-]{36}/revoke", account.text)) == 2
    revoked = await client.post(
        f"/account/sessions/{other_id}/revoke",
        data={"csrf_token": token_of(account)},
        headers=ORIGIN,
        follow_redirects=False,
    )
    assert (revoked.status_code, revoked.headers["location"]) == (303, "/account")
    still_logged_in = await client.get("/account")
    assert len(re.findall(r"/account/sessions/[0-9a-f-]{36}/revoke", still_logged_in.text)) == 1

    everywhere = await client.post(
        "/account/logout-all",
        data={"csrf_token": token_of(still_logged_in)},
        headers=ORIGIN,
        follow_redirects=False,
    )
    assert (everywhere.status_code, everywhere.headers["location"]) == (303, "/login")
    names = cookie_names(settings)
    cleared = {
        c.split("=")[0] for c in everywhere.headers.get_list("set-cookie") if "Max-Age=0" in c
    }
    assert {names.access, names.refresh} <= cleared
