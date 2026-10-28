"""Login, register, logout and account pages.

Tests without the ``db`` marker stay away from the database (no valid credentials involved).
The client keeps cookies between requests, like a browser.
"""

import re

import httpx
import pytest
from fastapi import FastAPI

from app.config import Settings
from app.middleware import cookie_names
from app.models import UserStatus
from tests.conftest import (
    GOOD_PASSWORD,
    ORIGIN,
    TEST_PASSWORD,
    TOKEN_FIELD,
    UserFactory,
    token_of,
    use_mode,
)

pytestmark = pytest.mark.anyio


async def post_form(
    client: httpx.AsyncClient, path: str, data: dict[str, str], *, token_from: str
) -> httpx.Response:
    """GET a page for a CSRF token, then POST the form to ``path`` like a browser would."""
    page = await client.get(token_from)
    return await client.post(
        path, data={**data, "csrf_token": token_of(page)}, headers=ORIGIN, follow_redirects=False
    )


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


async def test_register_page_follows_the_registration_mode(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings
) -> None:
    """`closed` hides the registration page (404); the other modes show it."""
    assert (await client.get("/register")).status_code == 200
    use_mode(app, settings, "closed")
    assert (await client.get("/register")).status_code == 404
    use_mode(app, settings, "open")
    assert (await client.get("/register")).status_code == 200


async def test_malformed_login_looks_like_a_wrong_password(client: httpx.AsyncClient) -> None:
    """A too long username is a plain failed login; the name shown again is HTML-escaped and the
    password is never echoed."""
    response = await post_form(
        client,
        "/login",
        {"username": "<b>x</b>" + "y" * 80, "password": "secret-value-1234"},
        token_from="/login",
    )
    assert response.status_code == 401
    assert "Invalid username or password." in response.text
    assert "secret-value-1234" not in response.text
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
async def test_login_with_a_dead_cookie_keeps_the_new_session(
    client: httpx.AsyncClient, settings: Settings, user_factory: UserFactory
) -> None:
    """A dead access cookie sent with the login form must not delete the new session's cookies."""
    await user_factory(username="anna")
    names = cookie_names(settings)
    page = await client.get("/login")
    csrf_cookie = f"{names.csrf}={client.cookies[names.csrf]}"
    # The Cookie header is set by hand, so the dead cookie certainly reaches the server (for
    # example a session revoked meanwhile).
    response = await client.post(
        "/login",
        data={"username": "anna", "password": TEST_PASSWORD, "csrf_token": token_of(page)},
        headers={**ORIGIN, "Cookie": f"{csrf_cookie}; {names.access}=garbage"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    written = [
        c for c in response.headers.get_list("set-cookie") if c.startswith(f"{names.access}=")
    ]
    assert len(written) == 1 and "Max-Age=0" not in written[0]
    assert (await client.get("/account", follow_redirects=False)).status_code == 200


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
    """Unknown user and wrong password: the same 401 page; pending accounts get a 403."""
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
    # Apart from the username shown again, the two pages are identical (no enumeration).
    assert re.sub(TOKEN_FIELD, "", unknown.text).replace("nobody", "") == (
        re.sub(TOKEN_FIELD, "", wrong.text).replace("anna", "")
    )
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


@pytest.mark.db
async def test_account_password_form_changes_the_password(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """Wrong current and weak new passwords show the page again (422) and change nothing.

    The right current password and a good new one redirect, show the banner, and the new password
    works at login.
    """
    await user_factory(username="anna")
    await post_form(
        client, "/login", {"username": "anna", "password": TEST_PASSWORD}, token_from="/login"
    )
    account = await client.get("/account")
    assert 'action="/account/password"' in account.text

    async def submit(current: str, new: str) -> httpx.Response:
        return await client.post(
            "/account/password",
            data={
                "csrf_token": token_of(account),
                "current_password": current,
                "new_password": new,
            },
            headers=ORIGIN,
            follow_redirects=False,
        )

    wrong = await submit("wrong-password-123", GOOD_PASSWORD)
    assert wrong.status_code == 422
    assert "Current password is wrong." in wrong.text

    weak = await submit(TEST_PASSWORD, "short")
    assert weak.status_code == 422
    assert "Password must be at least" in weak.text

    # Both failures left the password alone, so TEST_PASSWORD is still the current one.
    done = await submit(TEST_PASSWORD, GOOD_PASSWORD)
    assert (done.status_code, done.headers["location"]) == (303, "/account?password_changed=true")
    assert "Password changed." in (await client.get("/account?password_changed=true")).text
    login = await client.post(
        "/api/v1/auth/login", json={"username": "anna", "password": GOOD_PASSWORD}
    )
    assert login.status_code == 200


@pytest.mark.db
async def test_password_change_page_and_api_share_one_limit(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """5 per minute per user, counted once for the API and the form together.

    Five wrong guesses on the API are 422; then both the form and the API answer 429.
    """
    await user_factory(username="anna")
    await post_form(
        client, "/login", {"username": "anna", "password": TEST_PASSWORD}, token_from="/login"
    )
    token = (
        await client.post(
            "/api/v1/auth/login", json={"username": "anna", "password": TEST_PASSWORD}
        )
    ).json()["access_token"]
    for _ in range(5):
        response = await client.post(
            "/api/v1/me/password",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": "wrong-password-123", "new_password": GOOD_PASSWORD},
        )
        assert response.status_code == 422
    account = await client.get("/account")
    page = await client.post(
        "/account/password",
        data={
            "csrf_token": token_of(account),
            "current_password": "wrong-password-123",
            "new_password": GOOD_PASSWORD,
        },
        headers=ORIGIN,
    )
    assert page.status_code == 429
    again = await client.post(
        "/api/v1/me/password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "wrong-password-123", "new_password": GOOD_PASSWORD},
    )
    assert again.status_code == 429
