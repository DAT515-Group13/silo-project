"""/healthz, /readyz, the lifespan and the blob store selection."""

import logging
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from fastapi import FastAPI

from app import main
from app.db import get_db
from app.main import create_app
from tests.conftest import make_settings
from tests.fakes import InMemoryBlobStore


class FakeSession:
    """Stands in for an AsyncSession whose database answers ``SELECT 1``."""

    async def execute(self, statement: object) -> None:
        return None


@pytest.fixture
def healthy_database(app: FastAPI) -> Iterator[None]:
    """Replace the database dependency, so no PostgreSQL is needed."""

    async def fake_db() -> AsyncIterator[FakeSession]:
        yield FakeSession()

    app.dependency_overrides[get_db] = fake_db
    yield
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.anyio
async def test_healthz_checks_no_dependency(client: httpx.AsyncClient) -> None:
    """Liveness is 200 even though no database exists."""
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
@pytest.mark.usefixtures("healthy_database")
async def test_readyz_ok_when_both_dependencies_work(client: httpx.AsyncClient) -> None:
    """Readiness is 200 when SELECT 1 and the blob ping succeed."""
    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
@pytest.mark.usefixtures("healthy_database")
async def test_readyz_503_when_blob_store_fails(
    client: httpx.AsyncClient, blob_store: InMemoryBlobStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A failing ping gives 503; the body hides the cause, the log names it."""
    blob_store.healthy = False
    with caplog.at_level(logging.WARNING, logger="silo"):
        response = await client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert "blob storage (StorageUnavailable)" in caplog.text


@pytest.mark.anyio
async def test_readyz_503_when_database_is_unreachable(
    blob_store: InMemoryBlobStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A refused database connection gives 503 and the log never shows the DSN."""
    settings = make_settings(database_url="postgresql+asyncpg://user:pw-secret@127.0.0.1:1/none")
    app = create_app(settings=settings, blob_store=blob_store, initial_admin=False)
    transport = httpx.ASGITransport(app=app)
    with caplog.at_level(logging.WARNING, logger="silo"):
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                response = await client.get("/readyz")
    assert response.status_code == 503
    assert "database (" in caplog.text
    assert "pw-secret" not in caplog.text


@pytest.mark.db
@pytest.mark.anyio
async def test_readyz_ok_against_a_real_database(
    blob_store: InMemoryBlobStore, database_url: str
) -> None:
    """With PostgreSQL running (TEST_DATABASE_URL), /readyz is 200."""
    settings = make_settings(database_url=database_url)
    app = create_app(settings=settings, blob_store=blob_store, initial_admin=False)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.get("/readyz")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_injected_blob_store_is_not_closed_by_the_lifespan(
    app: FastAPI, blob_store: InMemoryBlobStore
) -> None:
    """The caller owns an injected store (tests close their own fakes)."""
    async with app.router.lifespan_context(app):
        assert app.state.blob_store is blob_store
    assert blob_store.closed is False


@pytest.mark.anyio
async def test_docs_follow_enable_docs() -> None:
    """/docs exists only when ENABLE_DOCS is true."""
    for enabled, expected in ((False, 404), (True, 200)):
        app = create_app(
            settings=make_settings(enable_docs=enabled),
            blob_store=InMemoryBlobStore(),
            initial_admin=False,
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            assert (await client.get("/docs")).status_code == expected
            assert (await client.get("/openapi.json")).status_code == expected


@pytest.mark.anyio
async def test_lifespan_creates_and_closes_the_azure_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without an injected store the lifespan calls create_blob_store(settings) once and
    closes that store at shutdown (the app owns it)."""
    created: list[object] = []

    def factory(settings: object) -> InMemoryBlobStore:
        store = InMemoryBlobStore()
        created.append(settings)
        created.append(store)
        return store

    monkeypatch.setattr(main, "create_blob_store", factory)
    settings = make_settings()
    app = create_app(settings=settings, initial_admin=False)
    async with app.router.lifespan_context(app):
        store = app.state.blob_store
        assert created == [settings, store]
        assert store.closed is False
    assert store.closed is True
    assert app.state.blob_store is None


@pytest.mark.anyio
async def test_readyz_503_when_the_database_does_not_answer(
    app: FastAPI, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A database that accepts the connection but hangs gives 503 after the timeout."""
    import asyncio

    from app.routers import health

    class HangingSession:
        async def execute(self, statement: object) -> None:
            await asyncio.sleep(30)

    async def hanging_db() -> AsyncIterator[HangingSession]:
        yield HangingSession()

    monkeypatch.setattr(health, "DATABASE_TIMEOUT_SECONDS", 0.05)
    app.dependency_overrides[get_db] = hanging_db
    response = await client.get("/readyz")
    assert response.status_code == 503


@pytest.mark.anyio
async def test_engine_is_disposed_when_startup_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing first-admin step must not leave the connection pool behind."""
    disposed: list[bool] = []
    real_create_engine = main.create_engine

    class SpyEngine:
        """Forwards everything to the real engine, but records ``dispose``."""

        def __init__(self, engine: object) -> None:
            self._engine = engine

        def __getattr__(self, name: str) -> object:
            return getattr(self._engine, name)

        async def dispose(self) -> None:
            disposed.append(True)
            await self._engine.dispose()  # type: ignore[attr-defined]

    def spying_create_engine(settings: object) -> SpyEngine:
        return SpyEngine(real_create_engine(settings))  # type: ignore[arg-type]

    async def failing_admin(*args: object, **kwargs: object) -> bool:
        raise RuntimeError("database trouble")

    monkeypatch.setattr(main, "create_engine", spying_create_engine)
    monkeypatch.setattr(main, "ensure_initial_admin", failing_admin)
    app = create_app(settings=make_settings(), blob_store=InMemoryBlobStore())
    with pytest.raises(RuntimeError):
        async with app.router.lifespan_context(app):
            pass
    assert disposed == [True]
