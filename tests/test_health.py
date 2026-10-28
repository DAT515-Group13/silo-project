"""/healthz, /readyz, the lifespan and the blob store selection."""

import asyncio
import logging

import httpx
import pytest
from fastapi import FastAPI

from app import main
from app.main import create_app
from app.routers import health
from tests.conftest import FakeSession, assert_secure, make_settings, sample
from tests.fakes import InMemoryBlobStore


@pytest.mark.anyio
async def test_healthz_checks_no_dependency(client: httpx.AsyncClient) -> None:
    """Liveness is 200 even though no database exists."""
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_readyz_ok_when_both_dependencies_work(
    client: httpx.AsyncClient, healthy_database: FakeSession
) -> None:
    """Readiness is 200 when SELECT 1 and the blob ping succeed; it also publishes the stored
    bytes (sum over all users) for the "storage almost full" alert."""
    healthy_database.used_bytes = 1234
    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert sample("silo_dependency_up", dependency="database") == 1
    assert sample("silo_dependency_up", dependency="blob_storage") == 1
    assert sample("silo_storage_used_bytes") == 1234
    # PostgreSQL aborts a slow sum itself (transaction-local statement_timeout, set before the
    # sum), so the request's connection is never cancelled mid-query.
    setting, total = healthy_database.statements[-2:]
    assert "set_config" in setting and "sum(users.used_bytes)" in total


@pytest.mark.anyio
@pytest.mark.usefixtures("healthy_database")
@pytest.mark.parametrize("problem", ["RuntimeError", "TimeoutError"])
async def test_a_failing_sum_never_makes_the_pod_unready(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    problem: str,
) -> None:
    """Telemetry must not take pods out of the Service: a broken or hanging sum is only logged,
    and a hanging one costs at most STORAGE_SUM_TIMEOUT_SECONDS."""

    async def broken(*args: object) -> int:
        if problem == "TimeoutError":
            await asyncio.sleep(30)
        raise RuntimeError("boom with a secret")

    monkeypatch.setattr(health, "STORAGE_SUM_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(health.users, "total_used_bytes", broken)
    with caplog.at_level(logging.WARNING, logger="silo"):
        async with asyncio.timeout(5):  # the probe itself must not hang
            response = await client.get("/readyz")
    assert response.status_code == 200
    assert f"stored bytes ({problem})" in caplog.text
    assert "secret" not in caplog.text  # only the exception type is logged


@pytest.mark.anyio
@pytest.mark.parametrize(("cap", "gauge"), [(0, 0), (500, 500)])
async def test_lifespan_publishes_the_storage_cap(
    blob_store: InMemoryBlobStore, cap: int, gauge: int
) -> None:
    """silo_storage_cap_bytes is STORAGE_TOTAL_MAX_BYTES at startup, 0 when there is no cap."""
    settings = make_settings(storage_total_max_bytes=cap)
    app = create_app(settings=settings, blob_store=blob_store, initial_admin=False)
    async with app.router.lifespan_context(app):
        assert sample("silo_storage_cap_bytes") == gauge


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("failing", "working", "logged"),
    [
        ("blob_storage", "database", "blob storage (StorageUnavailable)"),
        ("database", "blob_storage", "database (TimeoutError)"),  # accepts, never answers
    ],
)
async def test_readyz_503_when_one_dependency_fails(
    app: FastAPI,
    client: httpx.AsyncClient,
    blob_store: InMemoryBlobStore,
    healthy_database: FakeSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failing: str,
    working: str,
    logged: str,
) -> None:
    """One failing dependency gives 503 and sets only its own gauge to 0; the body hides the
    cause, the log names it. A hanging database is cut off after DATABASE_TIMEOUT_SECONDS."""
    if failing == "blob_storage":
        blob_store.healthy = False
    else:

        async def hang(statement: object) -> None:
            await asyncio.sleep(30)

        monkeypatch.setattr(healthy_database, "execute", hang)
        monkeypatch.setattr(health, "DATABASE_TIMEOUT_SECONDS", 0.05)
    with caplog.at_level(logging.WARNING, logger="silo"):
        response = await client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert logged in caplog.text
    assert sample("silo_dependency_up", dependency=failing) == 0
    assert sample("silo_dependency_up", dependency=working) == 1


@pytest.mark.anyio
async def test_readyz_503_when_database_is_unreachable(
    blob_store: InMemoryBlobStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A refused database connection gives 503, sets its gauge to 0, and the log never shows
    the DSN."""
    settings = make_settings(database_url="postgresql+asyncpg://user:pw-secret@127.0.0.1:1/none")
    app = create_app(settings=settings, blob_store=blob_store, initial_admin=False)
    transport = httpx.ASGITransport(app=app)
    with caplog.at_level(logging.WARNING, logger="silo"):
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                response = await client.get("/readyz")
    assert response.status_code == 503
    assert "database (" in caplog.text
    assert sample("silo_dependency_up", dependency="database") == 0
    assert "pw-secret" not in caplog.text
    assert "stored bytes" not in caplog.text  # no sum is tried on a database that is down


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
    assert sample("silo_storage_used_bytes") == 0  # the real SUM ran on the empty test database


@pytest.mark.anyio
async def test_docs_follow_enable_docs() -> None:
    """/docs exists only when ENABLE_DOCS is true; then it keeps all headers except the CSP.

    The docs page loads its script from a CDN, so it is the one page exempt from the CSP.
    """
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
            if enabled:
                assert_secure(await client.get("/docs"), csp=False)


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
