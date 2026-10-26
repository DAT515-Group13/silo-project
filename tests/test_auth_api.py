"""Auth and account API endpoints.

All tests go through HTTP and need PostgreSQL (marker ``db``).
"""

import httpx
import pytest
from fastapi import FastAPI

from app.config import Settings
from tests.conftest import GOOD_PASSWORD, TEST_PASSWORD, UserFactory, use_mode

pytestmark = [pytest.mark.db, pytest.mark.anyio]


async def login(
    client: httpx.AsyncClient, username: str = "anna", password: str = TEST_PASSWORD
) -> httpx.Response:
    return await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


def bearer(response: httpx.Response) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


# --- Register ----------------------------------------------------------------------------------


async def test_register_open_returns_201_and_the_user(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings
) -> None:
    """`open` mode: 201 with {id, username, role}; the new account can log in at once."""
    use_mode(app, settings, "open")
    response = await client.post(
        "/api/v1/auth/register", json={"username": "Anna", "password": GOOD_PASSWORD}
    )
    assert response.status_code == 201
    assert response.json() == {"id": 1, "username": "anna", "role": "user"}
    assert (await login(client, "anna", GOOD_PASSWORD)).status_code == 200


async def test_register_open_taken_is_409(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings, user_factory: UserFactory
) -> None:
    """`open` mode: a taken username gives 409 username_taken."""
    use_mode(app, settings, "open")
    await user_factory(username="anna")
    response = await client.post(
        "/api/v1/auth/register", json={"username": "anna", "password": GOOD_PASSWORD}
    )
    assert response.status_code == 409
    assert response.json()["code"] == "username_taken"


async def test_register_approval_answers_the_same_for_new_and_taken(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """`approval` mode (the default): identical 202 body for a new and an existing username."""
    await user_factory(username="taken")
    bodies = []
    for username in ("newcomer", "taken"):
        response = await client.post(
            "/api/v1/auth/register", json={"username": username, "password": GOOD_PASSWORD}
        )
        assert response.status_code == 202
        bodies.append(response.text)
    assert bodies[0] == bodies[1]
    assert "approve" in bodies[0]
    # The new account cannot log in until approved.
    refused = await login(client, "newcomer", GOOD_PASSWORD)
    assert (refused.status_code, refused.json()["code"]) == (403, "account_pending")


async def test_register_closed_is_404(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings
) -> None:
    """`closed` mode: the endpoint does not exist."""
    use_mode(app, settings, "closed")
    response = await client.post(
        "/api/v1/auth/register", json={"username": "anna", "password": GOOD_PASSWORD}
    )
    assert response.status_code == 404


# --- Login and refresh -------------------------------------------------------------------------


async def test_login_matches_example_9_1(
    client: httpx.AsyncClient, settings: Settings, user_factory: UserFactory
) -> None:
    """Login returns the token pair, lifetimes and the user (example 9.1)."""
    await user_factory(username="anna")
    response = await login(client)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "access_token",
        "refresh_token",
        "token_type",
        "expires_in",
        "refresh_expires_in",
        "user",
    }
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == settings.jwt_access_minutes * 60
    assert body["refresh_expires_in"] == settings.refresh_token_days * 86400
    assert len(body["refresh_token"]) == 43
    assert body["user"] == {"id": 1, "username": "anna", "role": "user"}


async def test_failed_logins_have_one_shape(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """Unknown user and wrong password: the same 401 body."""
    await user_factory(username="anna")
    unknown = await login(client, "nobody")
    wrong = await login(client, "anna", "wrong-password-123")
    assert unknown.status_code == wrong.status_code == 401
    assert (
        unknown.json()
        == wrong.json()
        == {
            "detail": "Invalid username or password.",
            "code": "invalid_credentials",
        }
    )


async def test_login_username_is_case_insensitive_and_lenient(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """Login lowercases the username; a name that could never be valid is simply a 401 (Q20)."""
    await user_factory(username="anna")
    assert (await login(client, "ANNA")).status_code == 200
    assert (await login(client, "not a valid name!")).status_code == 401


async def test_refresh_rotates_and_the_old_token_is_refused(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """A refresh gives a new pair; reusing the old token right away is 409."""
    await user_factory(username="anna")
    first = (await login(client)).json()
    response = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]}
    )
    assert response.status_code == 200
    assert response.json()["refresh_token"] != first["refresh_token"]
    again = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]}
    )
    assert (again.status_code, again.json()["code"]) == (409, "refresh_in_progress")
    unknown = await client.post("/api/v1/auth/refresh", json={"refresh_token": "nope"})
    assert (unknown.status_code, unknown.json()["code"]) == (401, "invalid_token")


# --- Account -----------------------------------------------------------------------------------


async def test_me_matches_example_9_2(
    client: httpx.AsyncClient, settings: Settings, user_factory: UserFactory
) -> None:
    """GET /me returns the user with usage and the quota of their role (example 9.2)."""
    await user_factory(username="anna", used_bytes=1048576)
    response = await client.get("/api/v1/me", headers=bearer(await login(client)))
    assert response.status_code == 200
    assert response.json() == {
        "id": 1,
        "username": "anna",
        "role": "user",
        "used_bytes": 1048576,
        "quota_bytes": settings.quota_user_bytes,
    }


async def test_sessions_list_matches_example_9_6(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """The list shows own active sessions and marks the one used for the request."""
    await user_factory(username="anna")
    first = await login(client)
    assert first.status_code == 200
    second = await login(client)
    response = await client.get("/api/v1/auth/sessions", headers=bearer(second))
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 2
    assert set(rows[0]) == {"id", "created_at", "last_used_at", "ip", "user_agent", "current"}
    assert sum(row["current"] for row in rows) == 1
    assert rows[0]["ip"] == "127.0.0.1"


async def test_delete_session_own_and_foreign(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """Deleting an own session gives 204 and kills its token; a foreign one gives 404."""
    await user_factory(username="anna")
    await user_factory(username="bob")
    anna1, anna2 = await login(client), await login(client)
    bob = await login(client, "bob")
    bobs_id = (await client.get("/api/v1/auth/sessions", headers=bearer(bob))).json()[0]["id"]
    mine = (await client.get("/api/v1/auth/sessions", headers=bearer(anna2))).json()
    other_of_mine = next(row["id"] for row in mine if not row["current"])

    assert (
        await client.delete(f"/api/v1/auth/sessions/{bobs_id}", headers=bearer(anna2))
    ).status_code == 404
    deleted = await client.delete(f"/api/v1/auth/sessions/{other_of_mine}", headers=bearer(anna2))
    assert deleted.status_code == 204
    assert (await client.get("/api/v1/me", headers=bearer(anna1))).status_code == 401
    assert (await client.get("/api/v1/me", headers=bearer(anna2))).status_code == 200


async def test_logout_takes_effect_immediately(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """After POST /auth/logout the access token is rejected at once."""
    await user_factory(username="anna")
    logged_in = await login(client)
    assert (await client.get("/api/v1/me", headers=bearer(logged_in))).status_code == 200
    assert (await client.post("/api/v1/auth/logout", headers=bearer(logged_in))).status_code == 204
    assert (await client.get("/api/v1/me", headers=bearer(logged_in))).status_code == 401


async def test_logout_all_ends_every_session(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """logout-all revokes all devices of the user, but not other users' sessions."""
    await user_factory(username="anna")
    await user_factory(username="bob")
    a1, a2, bob = await login(client), await login(client), await login(client, "bob")
    assert (await client.post("/api/v1/auth/logout-all", headers=bearer(a1))).status_code == 204
    assert (await client.get("/api/v1/me", headers=bearer(a1))).status_code == 401
    assert (await client.get("/api/v1/me", headers=bearer(a2))).status_code == 401
    assert (await client.get("/api/v1/me", headers=bearer(bob))).status_code == 200
