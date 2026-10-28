"""Auth and account API endpoints.

All tests go through HTTP and need PostgreSQL (marker ``db``).
"""

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.models import AuditLog, AuthSession, Outcome
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


async def test_register_open_creates_the_user_and_refuses_a_taken_name(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings
) -> None:
    """`open` mode: 201 with {id, username, role}, the account can log in; a taken name is 409."""
    use_mode(app, settings, "open")
    response = await client.post(
        "/api/v1/auth/register", json={"username": "Anna", "password": GOOD_PASSWORD}
    )
    assert response.status_code == 201
    assert response.json() == {"id": 1, "username": "anna", "role": "user"}
    assert (await login(client, "anna", GOOD_PASSWORD)).status_code == 200
    taken = await client.post(
        "/api/v1/auth/register", json={"username": "anna", "password": GOOD_PASSWORD}
    )
    assert (taken.status_code, taken.json()["code"]) == (409, "username_taken")


async def test_register_approval_answers_the_same_for_new_and_taken(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """`approval` mode (the default): identical 202 body for a new and an existing username.

    The existing account is not touched; only the audit log records `username_taken`.
    """
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
    assert (await login(client, "taken")).status_code == 200  # still active, same password
    async with db_sessionmaker() as db:
        reasons = (
            await db.scalars(
                select(AuditLog.details).where(
                    AuditLog.action == "auth.register", AuditLog.outcome == "denied"
                )
            )
        ).all()
    assert reasons == [{"reason": "username_taken"}]


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


async def test_sessions_list_and_delete_a_session(
    client: httpx.AsyncClient, user_factory: UserFactory
) -> None:
    """The list shows own active sessions and marks the current one (example 9.6).

    Deleting an own session gives 204 and kills its token; a foreign one gives 404.
    """
    await user_factory(username="anna")
    await user_factory(username="bob")
    anna1, anna2 = await login(client), await login(client)
    bob = await login(client, "bob")

    mine = (await client.get("/api/v1/auth/sessions", headers=bearer(anna2))).json()
    assert len(mine) == 2
    assert set(mine[0]) == {"id", "created_at", "last_used_at", "ip", "user_agent", "current"}
    assert sum(row["current"] for row in mine) == 1
    assert mine[0]["ip"] == "127.0.0.1"
    other_of_mine = next(row["id"] for row in mine if not row["current"])
    bobs_id = (await client.get("/api/v1/auth/sessions", headers=bearer(bob))).json()[0]["id"]

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
    """After POST /auth/logout the access token is rejected at once; other devices stay in."""
    await user_factory(username="anna")
    logged_in, other_device = await login(client), await login(client)
    assert (await client.get("/api/v1/me", headers=bearer(logged_in))).status_code == 200
    assert (await client.post("/api/v1/auth/logout", headers=bearer(logged_in))).status_code == 204
    assert (await client.get("/api/v1/me", headers=bearer(logged_in))).status_code == 401
    assert (await client.get("/api/v1/me", headers=bearer(other_device))).status_code == 200


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


# --- Password change ---------------------------------------------------------------------------


async def change_password(
    client: httpx.AsyncClient, headers: dict[str, str], current: str, new: str
) -> httpx.Response:
    return await client.post(
        "/api/v1/me/password",
        headers=headers,
        json={"current_password": current, "new_password": new},
    )


async def test_password_change_keeps_this_session_and_ends_the_others(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """204; only the old password stops working and only the other session ends.

    The ended session is marked `password_change` and one `auth.password_change` entry says
    how many sessions were revoked.
    """
    await user_factory(username="anna")
    here, other = await login(client), await login(client)
    response = await change_password(client, bearer(here), TEST_PASSWORD, GOOD_PASSWORD)
    assert response.status_code == 204
    assert (await client.get("/api/v1/me", headers=bearer(here))).status_code == 200
    assert (await client.get("/api/v1/me", headers=bearer(other))).status_code == 401
    async with db_sessionmaker() as db:
        reasons = (
            await db.scalars(select(AuthSession.revoked_reason).order_by(AuthSession.created_at))
        ).all()
        entries = (
            await db.execute(
                select(AuditLog.outcome, AuditLog.details).where(
                    AuditLog.action == "auth.password_change"
                )
            )
        ).all()
    assert reasons == [None, "password_change"]
    assert entries == [(Outcome.success, {"revoked": 1})]
    assert (await login(client, "anna", TEST_PASSWORD)).status_code == 401
    assert (await login(client, "anna", GOOD_PASSWORD)).status_code == 200


async def test_password_change_refuses_a_wrong_current_or_weak_new_password(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """422 on the bad field, a `failed` audit entry for a wrong current password, and the old
    password still works. The policy applies to the new password (too short, equal to the name).
    """
    await user_factory(username="anna")
    here = await login(client)
    response = await change_password(client, bearer(here), "wrong-password-123", GOOD_PASSWORD)
    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "current_password"
    async with db_sessionmaker() as db:
        outcomes = (
            await db.scalars(
                select(AuditLog.outcome).where(AuditLog.action == "auth.password_change")
            )
        ).all()
    assert outcomes == [Outcome.failed]

    for bad in ("short", "ANNA"):
        response = await change_password(client, bearer(here), TEST_PASSWORD, bad)
        assert response.status_code == 422
        assert response.json()["errors"][0]["field"] == "new_password"
    assert (await login(client, "anna", TEST_PASSWORD)).status_code == 200
