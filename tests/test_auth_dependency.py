"""Authentication of API requests, ``ApiUser``.

Tests without the ``db`` marker fail before any database access (bad or missing token).
"""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI

from app.config import Settings, get_settings
from app.models import AuthSession, User, UserStatus
from app.routers.api import admin, auth, files, links, teams
from app.routers.common import ApiUser, get_current_api_user
from app.services import sessions
from tests.conftest import (
    Sessionmaker,
    UserFactory,
    bearer,
    make_settings,
    route_calls,
    token_for,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def whoami(app: FastAPI) -> str:
    """Add a route that needs ApiUser to the app and return its path."""

    @app.get("/api/v1/_whoami")
    async def _whoami(user: ApiUser) -> dict[str, str | int]:
        return {"id": user.id, "username": user.username, "role": user.role.value}

    return "/api/v1/_whoami"


async def login(sm: Sessionmaker, settings: Settings, user: User) -> sessions.IssuedTokens:
    async with sm() as db, db.begin():
        return await sessions.create_session(db, settings, user)


# --- Failures that need no database ------------------------------------------------------


async def test_failures_look_the_same(
    client: httpx.AsyncClient, settings: Settings, whoami: str
) -> None:
    """Missing, malformed, forged, wrong-audience and expired tokens all give one identical 401."""
    sid = uuid.uuid4()
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    attempts = {
        "no header": {},
        "garbage": bearer("not-a-jwt"),
        "wrong scheme": {"Authorization": "Basic abc"},
        "bad signature": bearer(token_for(settings, 1, sid, secret="x" * 40)),
        "wrong audience": bearer(token_for(settings, 1, sid, audience="silo-prod")),
        "expired": bearer(token_for(settings, 1, sid, now=long_ago)),
    }
    responses = {name: await client.get(whoami, headers=h) for name, h in attempts.items()}
    for name, response in responses.items():
        assert response.status_code == 401, name
        assert response.headers["www-authenticate"] == "Bearer", name
    assert len({r.text for r in responses.values()}) == 1
    assert responses["no header"].json() == {
        "detail": "Invalid or expired token.",
        "code": "invalid_token",
    }


async def test_cookie_is_ignored_on_the_api(
    client: httpx.AsyncClient, settings: Settings, whoami: str
) -> None:
    """A valid-looking token in a cookie is not accepted on /api/v1.

    The Cookie header is set by hand, so the cookie is certainly sent.
    """
    token = token_for(settings, 1, uuid.uuid4())
    cookie = f"access_token={token}; __Host-access_token={token}"
    response = await client.get(whoami, headers={"Cookie": cookie})
    assert (response.status_code, response.json()["code"]) == (401, "invalid_token")


def test_every_api_route_needs_a_bearer_token_except_the_open_ones() -> None:
    """No /api/v1 route may forget ``ApiUser``; only register, login and refresh are open."""
    open_paths = {"/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/refresh"}
    checked, unprotected = 0, []
    for router in (auth.router, files.router, links.router, teams.router, admin.router):
        for route in router.routes:
            checked += 1
            if route.path not in open_paths and get_current_api_user not in route_calls(
                route.dependant
            ):
                unprotected.append(f"{sorted(route.methods)} {route.path}")
    assert checked > 30, "the test no longer finds the routes"
    assert unprotected == []


# --- Needs PostgreSQL --------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.parametrize("case", ["expired session", "disabled", "pending", "rejected"])
async def test_token_of_a_dead_session_or_inactive_user_is_rejected(
    client: httpx.AsyncClient,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    whoami: str,
    case: str,
) -> None:
    """A session past SESSION_MAX_DAYS is dead even if the JWT itself is still valid, and only
    status active may use the API (checked on every request)."""
    user = await user_factory()
    tokens = await login(db_sessionmaker, settings, user)
    headers = bearer(tokens.access_token)
    assert (await client.get(whoami, headers=headers)).status_code == 200
    async with db_sessionmaker() as db, db.begin():
        if case == "expired session":
            auth_session = await db.get_one(AuthSession, tokens.session_id)
            auth_session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        else:
            (await db.get_one(User, user.id)).status = UserStatus(case)
    assert (await client.get(whoami, headers=headers)).status_code == 401


@pytest.mark.db
async def test_session_of_another_user_is_rejected(
    client: httpx.AsyncClient,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    whoami: str,
) -> None:
    """`sub` must own `sid`, and `sid` must exist: anna's ID with bob's session or with a
    made-up session is invalid, although the token is correctly signed."""
    anna = await user_factory(username="anna")
    bob = await user_factory(username="bob")
    bobs = await login(db_sessionmaker, settings, bob)
    for session_id in (bobs.session_id, uuid.uuid4()):
        forged = token_for(settings, anna.id, session_id)
        assert (await client.get(whoami, headers=bearer(forged))).status_code == 401


@pytest.mark.db
async def test_previous_secret_is_accepted_during_rotation(
    app: FastAPI,
    client: httpx.AsyncClient,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    whoami: str,
) -> None:
    """A token signed with JWT_SECRET_PREVIOUS works only while that variable is set."""
    old_secret = "o" * 40
    database_url = settings.database_url.get_secret_value()
    user = await user_factory()
    tokens = await login(db_sessionmaker, settings, user)
    token = token_for(settings, user.id, tokens.session_id, secret=old_secret)

    # After rotation the new secret is JWT_SECRET and the old one is JWT_SECRET_PREVIOUS.
    with_previous = make_settings(
        database_url=database_url, jwt_secret="n" * 40, jwt_secret_previous=old_secret
    )
    app.dependency_overrides[get_settings] = lambda: with_previous
    assert (await client.get(whoami, headers=bearer(token))).status_code == 200

    # Once JWT_SECRET_PREVIOUS is removed, the old tokens stop working.
    without_previous = make_settings(database_url=database_url, jwt_secret="n" * 40)
    app.dependency_overrides[get_settings] = lambda: without_previous
    assert (await client.get(whoami, headers=bearer(token))).status_code == 401
