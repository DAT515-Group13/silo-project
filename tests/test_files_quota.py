"""Upload and quota behaviour end to end (architecture.md section 10).

All tests need PostgreSQL (marker ``db``): they go through HTTP with real tokens and check the
database, the audit log and the in-memory blob store together. The key promises: the quota is
never exceeded, even by parallel uploads, and a refused or failed upload leaves no blob.
"""

import asyncio

import httpx
import pytest
from sqlalchemy import func, select

from app.config import Settings
from app.models import AuditLog, File, User
from app.services import users as users_service
from app.services.users import QuotaStatus
from tests.conftest import BearerFor, Sessionmaker, UserFactory
from tests.fakes import InMemoryBlobStore

pytestmark = [pytest.mark.db, pytest.mark.anyio]


async def post_file(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    data: bytes,
    name: str = "a.txt",
    content_type: str = "text/plain",
) -> httpx.Response:
    return await client.post(
        "/api/v1/files", files={"file": (name, data, content_type)}, headers=headers
    )


async def used_bytes(db_sessionmaker: Sessionmaker, user_id: int) -> int:
    async with db_sessionmaker() as session:
        return await session.scalar(select(User.used_bytes).where(User.id == user_id))


async def count_files(db_sessionmaker: Sessionmaker) -> int:
    async with db_sessionmaker() as session:
        return await session.scalar(select(func.count()).select_from(File))


async def test_upload_stores_blob_row_quota_and_audit(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """A successful upload creates the blob, the row, the usage and one audit entry."""
    user = await user_factory("anna")
    headers = await bearer_for(user)
    response = await post_file(client, headers, b"%PDF-1.4 hello", "../report.pdf", "text/plain")
    assert response.status_code == 201, response.text
    body = response.json()
    # The name is cleaned and the type comes from the first bytes, not from the client.
    assert body["filename"] == "report.pdf"
    assert body["content_type"] == "application/pdf"
    assert body["size_bytes"] == 14
    assert body["is_owner"] is True
    assert "blob_name" not in body

    assert len(blob_store.blobs) == 1
    assert next(iter(blob_store.blobs.values())).data == b"%PDF-1.4 hello"
    assert await used_bytes(db_sessionmaker, user.id) == 14
    async with db_sessionmaker() as session:
        actions = (await session.scalars(select(AuditLog.action))).all()
    assert actions == ["file.upload"]


async def test_exact_quota_fits_and_one_byte_more_does_not(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The remaining quota is a hard limit; a refused upload leaves no blob (section 16)."""
    settings.quota_user_bytes = 100
    user = await user_factory("anna")
    headers = await bearer_for(user)

    assert (await post_file(client, headers, b"x" * 60)).status_code == 201
    refused = await post_file(client, headers, b"x" * 41)
    assert refused.status_code == 413
    assert refused.json()["code"] == "quota_exceeded"
    assert len(blob_store.blobs) == 1  # only the first upload
    assert await used_bytes(db_sessionmaker, user.id) == 60

    assert (await post_file(client, headers, b"x" * 40)).status_code == 201
    assert await used_bytes(db_sessionmaker, user.id) == 100
    # Full: even a tiny file is refused before anything is read.
    assert (await post_file(client, headers, b"x")).status_code == 413

    async with db_sessionmaker() as session:
        denied = (
            await session.scalars(select(AuditLog.outcome).where(AuditLog.outcome == "denied"))
        ).all()
    assert len(denied) == 2


async def test_file_over_the_size_limit_leaves_no_blob(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """MAX_FILE_SIZE_BYTES + 1 is 413 file_too_large and nothing is stored."""
    settings.max_file_size_bytes = 1000
    user = await user_factory("anna")
    headers = await bearer_for(user)

    assert (await post_file(client, headers, b"x" * 1000)).status_code == 201
    response = await post_file(client, headers, b"x" * 1001)
    assert response.status_code == 413
    assert response.json()["code"] == "file_too_large"
    assert len(blob_store.blobs) == 1
    assert await count_files(db_sessionmaker) == 1


async def test_parallel_uploads_at_the_edge_never_exceed_the_quota(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Two uploads that fit alone but not together: exactly one wins (section 16).

    Both requests are made to see the same stale "0 bytes used" status, so the early check
    cannot stop the second one and only the atomic UPDATE decides.
    """
    settings.quota_user_bytes = 100
    user = await user_factory("anna")
    headers = await bearer_for(user)

    async def stale_status(*args: object, **kwargs: object) -> QuotaStatus:
        return QuotaStatus(used_bytes=0, quota_bytes=100)

    monkeypatch.setattr(users_service, "get_quota_status", stale_status)

    results = await asyncio.gather(
        post_file(client, headers, b"a" * 70, "a.txt"),
        post_file(client, headers, b"b" * 70, "b.txt"),
    )
    assert sorted(r.status_code for r in results) == [201, 413]
    assert await used_bytes(db_sessionmaker, user.id) == 70
    assert await count_files(db_sessionmaker) == 1
    assert len(blob_store.blobs) == 1  # the loser's blob was deleted again


async def test_unavailable_storage_is_503_and_changes_nothing(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """If blob storage fails, the upload is 503 and no row or usage remains (section 11)."""
    user = await user_factory("anna")
    headers = await bearer_for(user)
    blob_store.healthy = False
    response = await post_file(client, headers, b"hello")
    assert response.status_code == 503
    assert response.json()["code"] == "storage_unavailable"
    assert await count_files(db_sessionmaker) == 0
    assert await used_bytes(db_sessionmaker, user.id) == 0


async def test_failed_database_step_deletes_the_blob(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Anything failing after the blob was stored removes the blob (upload step 5)."""
    user = await user_factory("anna")
    headers = await bearer_for(user)

    async def broken(*args: object, **kwargs: object) -> int:
        raise RuntimeError("database trouble")

    monkeypatch.setattr(users_service, "reserve_quota", broken)
    response = await post_file(client, headers, b"hello")
    assert response.status_code == 500  # the unexpected error becomes a plain 500
    assert blob_store.blobs == {}
    assert await count_files(db_sessionmaker) == 0
    assert await used_bytes(db_sessionmaker, user.id) == 0
