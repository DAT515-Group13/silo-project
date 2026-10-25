"""Authentication of API requests, ``ApiUser``.

Tests without the ``db`` marker fail before any database access (bad or missing token).
"""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI

from app.config import Settings, get_settings
from app.models import AuthSession, Role, User, UserStatus
from app.routers.common import ApiUser
from app.security import create_access_token
from app.services import sessions
from tests.conftest import Sessionmaker, UserFactory, make_settings

pytestmark = pytest.mark.anyio


@pytest.fixture
def whoami(app: FastAPI) -> str:
    """Add a route that needs ApiUser to the app and return its path."""

    @app.get("/api/v1/_whoami")
    async def _whoami(user: ApiUser) -> dict[str, str | int]:
        return {"id": user.id, "username": user.username, "role": user.role.value}

    return "/api/v1/_whoami"


def token_for(settings: Settings, user_id: int, session_id: uuid.UUID, **kwargs: object) -> str:
    """Create an access token the way the app does, with overridable values."""
    values: dict = {
        "user_id": user_id,
        "session_id": session_id,
        "secret": settings.jwt_secret.get_secret_value(),
        "issuer": settings.jwt_issuer,
        "audience": settings.jwt_audience,
        "ttl": timedelta(minutes=15),
    }
    return create_access_token(**{**values, **kwargs})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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


# --- Needs PostgreSQL --------------------------------------------------------------------


@pytest.mark.db
async def test_valid_token_gives_the_current_user(
    client: httpx.AsyncClient,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    whoami: str,
) -> None:
    """A valid token for an active session identifies the user."""
    user = await user_factory(username="anna", role=Role.team_lead)
    tokens = await login(db_sessionmaker, settings, user)
    response = await client.get(whoami, headers=bearer(tokens.access_token))
    assert response.status_code == 200
    assert response.json() == {"id": user.id, "username": "anna", "role": "team_lead"}


@pytest.mark.db
async def test_revoked_session_is_rejected_immediately(
    client: httpx.AsyncClient,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    whoami: str,
) -> None:
    """After logout the still unexpired access token stops working at once."""
    user = await user_factory()
    tokens = await login(db_sessionmaker, settings, user)
    headers = bearer(tokens.access_token)
    assert (await client.get(whoami, headers=headers)).status_code == 200
    async with db_sessionmaker() as db, db.begin():
        await sessions.revoke(db, user.id, tokens.session_id)
    response = await client.get(whoami, headers=headers)
    assert (response.status_code, response.json()["code"]) == (401, "invalid_token")


@pytest.mark.db
async def test_expired_session_is_rejected(
    client: httpx.AsyncClient,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    whoami: str,
) -> None:
    """A session past SESSION_MAX_DAYS is dead even if the JWT itself is still valid."""
    user = await user_factory()
    tokens = await login(db_sessionmaker, settings, user)
    async with db_sessionmaker() as db, db.begin():
        (await db.get_one(AuthSession, tokens.session_id)).expires_at = datetime.now(
            UTC
        ) - timedelta(seconds=1)
    assert (await client.get(whoami, headers=bearer(tokens.access_token))).status_code == 401


@pytest.mark.db
@pytest.mark.parametrize("status", [UserStatus.disabled, UserStatus.pending, UserStatus.rejected])
async def test_user_who_is_not_active_is_rejected(
    client: httpx.AsyncClient,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    whoami: str,
    status: UserStatus,
) -> None:
    """Only status active may use the API, checked on every request."""
    user = await user_factory()
    tokens = await login(db_sessionmaker, settings, user)
    async with db_sessionmaker() as db, db.begin():
        (await db.get_one(User, user.id)).status = status
    assert (await client.get(whoami, headers=bearer(tokens.access_token))).status_code == 401


@pytest.mark.db
async def test_session_of_another_user_is_rejected(
    client: httpx.AsyncClient,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    whoami: str,
) -> None:
    """`sub` must own `sid`: a token pairing anna's ID with bob's session is invalid."""
    anna = await user_factory(username="anna")
    bob = await user_factory(username="bob")
    bobs = await login(db_sessionmaker, settings, bob)
    forged = token_for(settings, anna.id, bobs.session_id)
    assert (await client.get(whoami, headers=bearer(forged))).status_code == 401


@pytest.mark.db
async def test_unknown_session_is_rejected(
    client: httpx.AsyncClient, settings: Settings, user_factory: UserFactory, whoami: str
) -> None:
    """A correctly signed token for a session that does not exist is invalid."""
    user = await user_factory()
    forged = token_for(settings, user.id, uuid.uuid4())
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
