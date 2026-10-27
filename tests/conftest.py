"""Shared fixtures.

Tests that need PostgreSQL carry the marker ``db``. Only they touch the database: the server comes
from ``TEST_DATABASE_URL`` and its schema is rebuilt once per session with ``alembic upgrade
head``. After each ``db`` test every table is emptied, so tests cannot affect each other and
concurrency tests can use real, separate connections (no rollback per test).

The ``blob_store`` fixture is an ``InMemoryBlobStore``, a new one for every test.
"""

import asyncio
import os
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from prometheus_client import REGISTRY
from sqlalchemy import text, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.config import Settings, get_settings
from app.db import get_db
from app.main import create_app
from app.middleware import cookie_names
from app.models import Base, File, FileShare, Role, User, UserStatus
from app.permissions import CurrentUser
from app.routers.common import get_current_api_user, get_optional_page_user
from app.security import create_access_token, create_csrf_token, hash_password
from app.services import sessions
from tests.fakes import InMemoryBlobStore

ROOT = Path(__file__).resolve().parent.parent


def sample(name: str, **labels: str) -> float:
    """Current value of one Prometheus time series; 0 if it does not exist yet."""
    return REGISTRY.get_sample_value(name, labels) or 0.0


# Page forms: the Origin header of this site and the hidden CSRF field of a rendered form.
ORIGIN = {"Origin": "http://testserver"}
TOKEN_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')

# Default: the compose PostgreSQL with user and password "silo". The password in .env.dev.example
# is a CHANGE placeholder, so set TEST_DATABASE_URL to match your own .env.dev.
DEFAULT_TEST_DATABASE_URL = "postgresql+asyncpg://silo:silo@localhost:5432/silo_test"
ALL_TABLES = ", ".join(Base.metadata.tables)
TEST_PASSWORD = "correct-horse-battery-staple"


def make_settings(**overrides: Any) -> Settings:
    """Build valid test settings without reading the environment; keyword arguments override."""
    values: dict[str, Any] = {
        "app_env": "test",
        "base_url": "http://testserver",
        "database_url": DEFAULT_TEST_DATABASE_URL,
        "azure_storage_connection_string": "UseTestValue",
        "azure_storage_container": "silo-test",
        "jwt_secret": "j" * 32,
        "jwt_issuer": "silo",
        "jwt_audience": "silo-test",
        "csrf_secret": "c" * 32,
        "cookie_secure": False,
        "initial_admin_username": "admin",
        "initial_admin_password": "test-admin-password",
        "max_file_size_bytes": 10 * 1024 * 1024,
    }
    return Settings(_env_file=None, **{**values, **overrides})  # type: ignore[call-arg]


Sessionmaker = async_sessionmaker[AsyncSession]
GOOD_PASSWORD = "a-long-enough-password"


def use_mode(app: FastAPI, settings: Settings, mode: str) -> None:
    """Run the app with another REGISTRATION_MODE (same database)."""
    changed = make_settings(
        database_url=settings.database_url.get_secret_value(), registration_mode=mode
    )
    app.dependency_overrides[get_settings] = lambda: changed


def token_of(response: httpx.Response) -> str:
    """The CSRF token a rendered form carries in its hidden field."""
    match = TOKEN_FIELD.search(response.text)
    assert match, "no csrf_token field in the page"
    return match.group(1)


@pytest.fixture(autouse=True)
def _clean_settings_env(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ignore app variables set in the shell, so settings are the same on every machine.

    Tests marked ``azure`` are left alone: they read the real Azure variables.
    """
    if request.node.get_closest_marker("azure") is not None:
        return
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


@pytest.fixture
def blob_store() -> InMemoryBlobStore:
    """The fake blob store injected into the app (a new, empty one for every test)."""
    return InMemoryBlobStore()


# --- Database ------------------------------------------------------------------------------------


def _server_url() -> str:
    """The database URL tests use (TEST_DATABASE_URL or the compose default)."""
    return os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


def _require_test_database(url: str) -> None:
    """Refuse any database whose name does not end in _test: the setup drops its schema."""
    name = make_url(url).database or ""
    if not name.endswith("_test"):
        raise RuntimeError(f"TEST_DATABASE_URL must name a database ending in _test, not {name!r}.")


async def _prepare_database(url: str) -> None:
    """Create the test database if it is missing and wipe the ``public`` schema."""
    target = make_url(url)
    admin = create_async_engine(
        target.set(database="postgres"), isolation_level="AUTOCOMMIT", poolclass=NullPool
    )
    async with admin.connect() as connection:
        exists = await connection.scalar(
            text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": target.database}
        )
        if not exists:
            await connection.execute(text(f'CREATE DATABASE "{target.database}"'))
    await admin.dispose()

    # A fresh schema, so leftovers of an older run (or older migration) cannot hide a problem.
    engine = create_async_engine(url, poolclass=NullPool)
    async with engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
    await engine.dispose()


@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    """URL of a migrated, empty test database (built once per session, only for ``db`` tests)."""
    url = _server_url()
    _require_test_database(url)
    asyncio.run(_prepare_database(url))
    # The Alembic environment reads DATABASE_URL (D13).
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    try:
        # Absolute paths, so pytest can be started from any directory.
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(ROOT / "migrations"))
        command.upgrade(config, "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
    yield url


async def _truncate(url: str) -> None:
    engine = create_async_engine(url, poolclass=NullPool)
    async with engine.begin() as connection:
        await connection.execute(text(f"TRUNCATE {ALL_TABLES} RESTART IDENTITY CASCADE"))
    await engine.dispose()


@pytest.fixture(autouse=True)
def _clean_database(request: pytest.FixtureRequest) -> Iterator[None]:
    """For ``db`` tests: build the schema first, empty every table afterwards."""
    if request.node.get_closest_marker("db") is None:
        yield
        return
    url = request.getfixturevalue("database_url")
    yield
    asyncio.run(_truncate(url))


@pytest.fixture
async def db_engine(request: pytest.FixtureRequest) -> AsyncIterator[AsyncEngine]:
    """An engine on the test database, created per test so it belongs to the test's event loop."""
    engine = create_async_engine(request.getfixturevalue("database_url"), poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest.fixture
def db_sessionmaker(db_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory on the test database; services open their own transactions with it."""
    return async_sessionmaker(db_engine, expire_on_commit=False)


@pytest.fixture(scope="session")
def test_password_hash() -> str:
    """Argon2 hash of ``TEST_PASSWORD``, computed once (hashing is deliberately slow)."""
    return asyncio.run(hash_password(TEST_PASSWORD))


UserFactory = Callable[..., Awaitable[User]]


@pytest.fixture
def user_factory(
    db_sessionmaker: async_sessionmaker[AsyncSession], test_password_hash: str
) -> UserFactory:
    """Create users in the test database.

    ``await user_factory(username="anna", role=Role.team_lead, status=UserStatus.active)``.
    Every user has the password ``TEST_PASSWORD`` unless ``password_hash`` is given. Users are
    active regular users by default, which is what most tests need.
    """

    async def create(
        username: str = "anna",
        role: Role = Role.user,
        status: UserStatus = UserStatus.active,
        **fields: Any,
    ) -> User:
        user = User(
            username=username.lower(),
            password_hash=fields.pop("password_hash", test_password_hash),
            role=role,
            status=status,
            **fields,
        )
        async with db_sessionmaker() as session, session.begin():
            session.add(user)
            await session.flush()
            # Load the server-side defaults (created_at, ...) while the session is open.
            await session.refresh(user)
        return user

    return create


FileFactory = Callable[..., Awaitable[File]]


@pytest.fixture
def file_factory(db_sessionmaker: async_sessionmaker[AsyncSession]) -> FileFactory:
    """Insert file rows directly: ``await file_factory(owner_id, team_id=None, size_bytes=10)``.

    Only the metadata row (and optionally a share with ``team_id``); no blob is written. The
    blob name is random, as in the real upload flow. The size is added to the owner's
    ``used_bytes`` like a real upload, so deleting the file later cannot push the counter below
    zero (the CHECK constraint would turn that into a 500).
    """

    async def create(owner_id: int, team_id: int | None = None, **fields: Any) -> File:
        values = {
            "filename": "report.pdf",
            "content_type": "application/pdf",
            "size_bytes": 10,
            "blob_name": uuid.uuid4().hex,
            **fields,
        }
        async with db_sessionmaker() as session, session.begin():
            file = File(owner_id=owner_id, **values)
            session.add(file)
            await session.execute(
                update(User)
                .where(User.id == owner_id)
                .values(used_bytes=User.used_bytes + values["size_bytes"])
            )
            await session.flush()
            if team_id is not None:
                session.add(FileShare(file_id=file.id, team_id=team_id))
            await session.refresh(file)
        return file

    return create


# --- App and client ------------------------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings(request: pytest.FixtureRequest) -> Settings:
    """Valid settings. ``db`` tests get the real test database; other tests a dummy URL."""
    if request.node.get_closest_marker("db") is not None:
        return make_settings(database_url=request.getfixturevalue("database_url"))
    return make_settings()


@pytest.fixture
def app(settings: Settings, blob_store: InMemoryBlobStore) -> FastAPI:
    """The real app with injected settings and fake blob store."""
    return create_app(settings=settings, blob_store=blob_store, initial_admin=False)


ActAs = Callable[..., CurrentUser]


class FakeSession:
    """Stands in for an AsyncSession: ``SELECT 1`` works and ``SUM(used_bytes)`` is ``used_bytes``.

    Every statement is recorded in ``statements`` (as SQL text), so a test can check what was
    asked and in which order. ``begin()`` is a no-op transaction.
    """

    def __init__(self, used_bytes: int = 0) -> None:
        self.used_bytes = used_bytes
        self.statements: list[str] = []

    def begin(self) -> "FakeSession":
        return self

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def execute(self, statement: object) -> None:
        self.statements.append(str(statement))

    async def scalar(self, statement: object) -> int:
        self.statements.append(str(statement))
        return self.used_bytes


@pytest.fixture
def healthy_database(app: FastAPI) -> Iterator[FakeSession]:
    """Replace the database dependency, so no PostgreSQL is needed; yields the fake session."""
    session = FakeSession()

    async def fake_db() -> AsyncIterator[FakeSession]:
        yield session

    app.dependency_overrides[get_db] = fake_db
    yield session
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def act_as(app: FastAPI) -> ActAs:
    """Pretend a user is logged in on both surfaces, without tokens or a database.

    ``user = act_as(Role.user, user_id=1)``. Only for tests that fail or finish before the
    service touches the database (permission checks, validation, role checks).
    """

    def login(role: Role = Role.user, user_id: int = 1, username: str = "anna") -> CurrentUser:
        user = CurrentUser(id=user_id, username=username, role=role, session_id=uuid.uuid4())
        app.dependency_overrides[get_current_api_user] = lambda: user
        app.dependency_overrides[get_optional_page_user] = lambda: user
        return user

    return login


BearerFor = Callable[[User], Awaitable[dict[str, str]]]


@pytest.fixture
def bearer_for(db_sessionmaker: async_sessionmaker[AsyncSession], settings: Settings) -> BearerFor:
    """``headers = await bearer_for(user)``: a real session and its Authorization header."""

    async def create(user: User) -> dict[str, str]:
        async with db_sessionmaker() as session, session.begin():
            tokens = await sessions.create_session(session, settings, user)
        return {"Authorization": f"Bearer {tokens.access_token}"}

    return create


def page_csrf(settings: Settings, user: CurrentUser) -> tuple[dict[str, str], dict[str, str]]:
    """Cookie and Origin headers plus form data with a valid CSRF token for ``user``'s session."""
    token = create_csrf_token(settings.csrf_secret.get_secret_value(), str(user.session_id))
    headers = {
        "Cookie": f"{cookie_names(settings).csrf}={token}",
        "Origin": settings.base_url,
    }
    return headers, {"csrf_token": token}


PageLogin = Callable[[User], Awaitable[tuple[dict[str, str], dict[str, str]]]]


@pytest.fixture
def page_login(db_sessionmaker: Sessionmaker, settings: Settings) -> PageLogin:
    """``headers, form = await page_login(user)``: access cookie, CSRF cookie and form field."""

    async def login(user: User) -> tuple[dict[str, str], dict[str, str]]:
        async with db_sessionmaker() as session, session.begin():
            tokens = await sessions.create_session(session, settings, user)
        names = cookie_names(settings)
        csrf = create_csrf_token(settings.csrf_secret.get_secret_value(), str(tokens.session_id))
        headers = {
            "Cookie": f"{names.access}={tokens.access_token}; {names.csrf}={csrf}",
            "Origin": settings.base_url,
        }
        return headers, {"csrf_token": csrf}

    return login


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """ASGI client. The lifespan runs, so the engine and session factory exist."""
    # raise_app_exceptions=False so the 500 handler can be tested.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


# --- Team helpers over the API (used by the team and file tests) ---------------------------------


async def make_team(client: httpx.AsyncClient, headers: dict, name: str = "Design") -> int:
    """Create a team as the logged-in user of ``headers`` and return its ID."""
    response = await client.post("/api/v1/teams", json={"name": name}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["id"]


async def add_member(client: httpx.AsyncClient, headers: dict, team_id: int, username: str) -> int:
    """Add a member through the API and return the status code (always 204 when allowed)."""
    response = await client.post(
        f"/api/v1/teams/{team_id}/members", json={"username": username}, headers=headers
    )
    return response.status_code


# --- Small helpers shared by several test files --------------------------------------------------


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
    """The Authorization header for an access token."""
    return {"Authorization": f"Bearer {token}"}


def route_calls(dependant) -> set:
    """Every function a route depends on, directly or through other dependencies."""
    found = {dependant.call}
    for sub in dependant.dependencies:
        found |= route_calls(sub)
    return found


async def post(
    client: httpx.AsyncClient, login: tuple[dict, dict], path: str, **fields: str
) -> httpx.Response:
    """POST a page form as the user of ``page_login``: cookies, Origin and CSRF field included."""
    headers, form = login
    return await client.post(path, data={**form, **fields}, headers=headers, follow_redirects=False)
