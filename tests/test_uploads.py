"""Uploads over HTTP: the early refusals, the quota and what a failed upload leaves behind.

Tests without the ``db`` marker stop before the database: ``act_as`` replaces the login and a
stand-in replaces the upload service (bad bodies, the 3-at-a-time limit, draining a refused
body). The ``db`` tests go through HTTP with real tokens and check the database, the audit log
and the in-memory blob store together. The key promises: the quota is never exceeded, even by
parallel uploads, and a refused or failed upload leaves no blob.
"""

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack

import httpx
import pytest
from sqlalchemy import select

from app.config import Settings
from app.errors import FileTooLarge, StorageFull, StorageUnavailable
from app.models import AuditLog, Role
from app.permissions import CurrentUser
from app.ratelimit import _FALLBACK_RETRY_AFTER as FALLBACK_RETRY_AFTER
from app.ratelimit import MAX_CONCURRENT_UPLOADS, upload_slot
from app.services import files
from app.services import users as users_service
from app.services.audit import AuditContext
from app.services.users import QuotaStatus
from tests.conftest import (
    ActAs,
    BearerFor,
    FakeSession,
    Sessionmaker,
    UserFactory,
    audit_actions,
    count_files,
    sample,
    used_bytes,
)
from tests.fakes import InMemoryBlobStore

pytestmark = pytest.mark.anyio
db = pytest.mark.db

BOUNDARY = "testboundary"
CHUNK_COUNT = 20


# --- No database needed --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_args",
    [
        {"json": {"file": "x"}},  # not multipart
        {"files": {"file": ("", b"", "application/octet-stream")}},  # no file chosen
    ],
)
async def test_upload_with_a_bad_body_is_422(
    client: httpx.AsyncClient, act_as: ActAs, request_args: dict
) -> None:
    """A JSON body or an empty file name is a 422, not a crash.

    A wrong part name is in ``test_refused_upload_still_reads_the_whole_body``.
    """
    act_as(Role.user)
    response = await client.post("/api/v1/files", **request_args)
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


@pytest.mark.parametrize(
    ("extra", "drained"),
    [
        (1024 * 1024, True),  # over the limit, under the drain cap (+ 5 MiB): the rest is read
        (10**9, False),  # announced far over the cap: draining could not finish, so it is skipped
    ],
)
async def test_oversized_content_length_is_413_and_drains_only_below_the_cap(
    client: httpx.AsyncClient,
    act_as: ActAs,
    settings: Settings,
    blob_store: InMemoryBlobStore,
    extra: int,
    drained: bool,
) -> None:
    """A Content-Length over the limit is refused before any blob work.

    A body that is still small enough is read to the end before the 413 is sent, otherwise the
    proxy can turn the 413 into a 502. The denied-upload audit entry cannot be written
    without a database; that is only logged.
    """
    act_as(Role.user)
    sent: list[int] = []
    head = b'--b\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'

    async def body() -> AsyncIterator[bytes]:
        yield head
        for i in range(20):
            sent.append(i)
            yield b"x" * 1000
        yield b"\r\n--b--\r\n"

    response = await client.post(
        "/api/v1/files",
        content=body(),
        headers={
            "content-type": "multipart/form-data; boundary=b",
            "content-length": str(settings.max_file_size_bytes + extra),
        },
    )
    assert (response.status_code, response.json()["code"]) == (413, "file_too_large")
    assert blob_store.blobs == {}
    assert (len(sent) == 20) is drained


async def test_fourth_parallel_upload_is_429(
    client: httpx.AsyncClient, act_as: ActAs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three uploads of one user run at once; the fourth is 429 rate_limited until one ends."""
    act_as(Role.user)
    release = asyncio.Event()
    all_running = asyncio.Event()
    running = 0

    async def held_upload(*args: object, **kwargs: object) -> None:
        nonlocal running
        running += 1
        if running == MAX_CONCURRENT_UPLOADS:
            all_running.set()
        await release.wait()
        raise FileTooLarge  # any ending will do; the test is about the slots

    monkeypatch.setattr(files, "upload", held_upload)

    async def upload() -> httpx.Response:
        return await client.post("/api/v1/files", files={"file": ("a.bin", b"data")})

    tasks = [asyncio.create_task(upload()) for _ in range(MAX_CONCURRENT_UPLOADS)]
    try:
        async with asyncio.timeout(5):
            await all_running.wait()

        fourth = await upload()
        assert (fourth.status_code, fourth.json()["code"]) == (429, "rate_limited")
        assert fourth.headers["retry-after"] == str(FALLBACK_RETRY_AFTER)
    finally:
        # Also after a failure: held uploads would keep their slots for the next test.
        release.set()
    results = await asyncio.gather(*tasks)
    assert [r.status_code for r in results] == [413] * MAX_CONCURRENT_UPLOADS
    assert running == MAX_CONCURRENT_UPLOADS  # the fourth never reached the service


@pytest.mark.parametrize(
    ("case", "status", "code"),
    [
        ("busy", 429, "rate_limited"),
        ("wrong part", 422, "validation_error"),
        ("service full", 507, "storage_full"),
        ("storage outage", 503, "storage_unavailable"),
    ],
)
async def test_refused_upload_still_reads_the_whole_body(
    client: httpx.AsyncClient,
    act_as: ActAs,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    status: int,
    code: str,
) -> None:
    """A refused upload is answered after the rest of the body was read (no proxy 502).

    "service full" stands for the global cap: ``StorageFull`` is a ``QuotaExceeded``, so the
    route drains the body and answers 507 without any route change. "storage outage" fails
    before reading the file too, so the whole body is left to drain.
    """
    user = act_as(Role.user)
    field = "other" if case == "wrong part" else "file"  # a part that is not `file` is a 422
    sent = 0

    async def full(*args: object, **kwargs: object) -> None:
        raise StorageFull  # refused before reading the file, like the quota check before the upload

    async def outage(*args: object, **kwargs: object) -> None:
        raise StorageUnavailable

    if case == "service full":
        monkeypatch.setattr(files, "upload", full)
    elif case == "storage outage":
        monkeypatch.setattr(files, "upload", outage)

    async def body() -> AsyncIterator[bytes]:
        nonlocal sent
        head = f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{field}"; '
        yield (head + 'filename="a.bin"\r\n\r\n').encode()
        sent += 1
        for _ in range(CHUNK_COUNT):
            yield b"x" * 1000
            sent += 1
        yield f"\r\n--{BOUNDARY}--\r\n".encode()
        sent += 1

    async with AsyncExitStack() as stack:
        if case == "busy":  # all slots of this user are taken by other uploads
            for _ in range(MAX_CONCURRENT_UPLOADS):
                await stack.enter_async_context(upload_slot(user.id))
        response = await client.post(
            "/api/v1/files",
            content=body(),
            headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
        )

    assert (response.status_code, response.json()["code"]) == (status, code)
    assert sent == CHUNK_COUNT + 2  # the client could send everything


async def test_cancelled_request_deletes_the_blob_it_already_stored(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, blob_store: InMemoryBlobStore
) -> None:
    """A request cancelled after the blob was stored (the client left) removes the blob again."""

    async def free_quota(*args: object, **kwargs: object) -> QuotaStatus:
        return QuotaStatus(used_bytes=0, quota_bytes=100)

    async def cancelled(*args: object, **kwargs: object) -> None:
        raise asyncio.CancelledError

    async def chunks() -> AsyncIterator[bytes]:
        yield b"hello"

    monkeypatch.setattr(users_service, "get_quota_status", free_quota)
    monkeypatch.setattr(users_service, "reserve_quota", cancelled)

    with pytest.raises(asyncio.CancelledError):
        await files.upload(
            FakeSession(),
            settings,
            blob_store,
            CurrentUser(1, "anna", Role.user, uuid.uuid4()),
            AuditContext.system(),
            filename="a.txt",
            client_type=None,
            chunks=chunks(),
            declared_size=None,
        )

    assert blob_store.blobs == {}
    assert len(blob_store.deleted) == 1


# --- Needs PostgreSQL ----------------------------------------------------------------------------


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


@db
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
    ok_before = sample("silo_uploads_total", result="ok")
    bytes_before = sample("silo_upload_bytes_total")
    response = await post_file(client, headers, b"%PDF-1.4 hello", "../report.pdf", "text/plain")
    assert response.status_code == 201, response.text
    body = response.json()
    # The name is cleaned and the type comes from the first bytes, not from the client.
    assert body["filename"] == "report.pdf"
    assert body["content_type"] == "application/pdf"
    assert body["size_bytes"] == 14
    assert body["is_owner"] is True
    assert "blob_name" not in body
    assert sample("silo_uploads_total", result="ok") == ok_before + 1
    assert sample("silo_upload_bytes_total") == bytes_before + 14

    assert len(blob_store.blobs) == 1
    assert next(iter(blob_store.blobs.values())).data == b"%PDF-1.4 hello"
    assert await used_bytes(db_sessionmaker, user.id) == 14
    actions = await audit_actions(db_sessionmaker)
    assert actions == ["file.upload"]


@db
async def test_exact_quota_fits_and_one_byte_more_does_not(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The remaining quota is a hard limit; a refused upload leaves no blob."""
    settings.quota_user_bytes = 100
    user = await user_factory("anna")
    headers = await bearer_for(user)

    assert (await post_file(client, headers, b"x" * 60)).status_code == 201
    refused_before = sample("silo_uploads_total", result="quota_exceeded")
    refused = await post_file(client, headers, b"x" * 41)
    assert refused.status_code == 413
    assert refused.json()["code"] == "quota_exceeded"
    assert sample("silo_uploads_total", result="quota_exceeded") == refused_before + 1
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


@db
async def test_file_over_the_size_limit_leaves_no_blob(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """MAX_FILE_SIZE_BYTES + 1 is 413 file_too_large, nothing is stored and it is audited."""
    settings.max_file_size_bytes = 1000
    user = await user_factory("anna")
    headers = await bearer_for(user)

    assert (await post_file(client, headers, b"x" * 1000)).status_code == 201
    large_before = sample("silo_uploads_total", result="too_large")
    response = await post_file(client, headers, b"x" * 1001)
    assert response.status_code == 413
    assert response.json()["code"] == "file_too_large"
    assert sample("silo_uploads_total", result="too_large") == large_before + 1
    assert len(blob_store.blobs) == 1
    assert await count_files(db_sessionmaker) == 1
    async with db_sessionmaker() as session:
        codes = (
            await session.scalars(
                select(AuditLog.details["code"].astext).where(AuditLog.outcome == "denied")
            )
        ).all()
    assert codes == ["file_too_large"]


@db
async def test_parallel_uploads_at_the_edge_never_exceed_the_quota(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Two uploads that fit alone but not together: exactly one wins.

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


@db
async def test_unavailable_storage_is_503_and_changes_nothing(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """If blob storage fails, the upload is 503 and no row or usage remains."""
    user = await user_factory("anna")
    headers = await bearer_for(user)
    blob_store.healthy = False
    response = await post_file(client, headers, b"hello")
    assert response.status_code == 503
    assert response.json()["code"] == "storage_unavailable"
    assert await count_files(db_sessionmaker) == 0
    assert await used_bytes(db_sessionmaker, user.id) == 0


@db
async def test_interrupted_upload_leaves_nothing_and_frees_its_slot(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """A body cut off inside the file is a 422 and changes nothing.

    It is repeated once per upload slot: a slot that was not released would make the last upload
    a 429.
    """
    user = await user_factory("anna")
    headers = await bearer_for(user)

    async def cut_off() -> AsyncIterator[bytes]:
        yield b'--b\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'
        yield b"x" * 1000  # the closing boundary never comes

    for _ in range(MAX_CONCURRENT_UPLOADS):
        response = await client.post(
            "/api/v1/files",
            content=cut_off(),
            headers={**headers, "Content-Type": "multipart/form-data; boundary=b"},
        )
        assert (response.status_code, response.json()["code"]) == (422, "validation_error")

    assert blob_store.blobs == {}
    assert await count_files(db_sessionmaker) == 0
    assert await used_bytes(db_sessionmaker, user.id) == 0
    assert (await post_file(client, headers, b"hello")).status_code == 201


@db
async def test_failed_database_step_deletes_the_blob(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Anything failing after the blob was stored removes the blob."""
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


@db
async def test_global_cap_refuses_with_507_and_leaves_no_blob(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Uploads of all users share STORAGE_TOTAL_MAX_BYTES; over it is 507 storage_full."""
    settings.storage_total_max_bytes = 100
    anna = await user_factory("anna")
    bob = await user_factory("bob")
    bob_headers = await bearer_for(bob)

    assert (await post_file(client, await bearer_for(anna), b"x" * 60)).status_code == 201
    refused_before = sample("silo_uploads_total", result="storage_full")
    refused = await post_file(client, bob_headers, b"x" * 41)
    assert refused.status_code == 507
    assert refused.json()["code"] == "storage_full"
    assert sample("silo_uploads_total", result="storage_full") == refused_before + 1
    assert len(blob_store.blobs) == 1
    assert await used_bytes(db_sessionmaker, bob.id) == 0

    assert (await post_file(client, bob_headers, b"x" * 40)).status_code == 201
    # Full: even a tiny file is refused before anything is read.
    assert (await post_file(client, bob_headers, b"x")).status_code == 507

    async with db_sessionmaker() as session:
        codes = (
            await session.scalars(
                select(AuditLog.details["code"].astext).where(AuditLog.outcome == "denied")
            )
        ).all()
    assert codes == ["storage_full", "storage_full"]


@db
async def test_parallel_uploads_of_two_users_at_the_global_edge(
    client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Two users whose files fit alone but not together: exactly one wins.

    Both see the same stale "everything is free" hint, so only the locked quota check decides.
    """
    settings.storage_total_max_bytes = 100
    anna = await user_factory("anna")
    bob = await user_factory("bob")

    async def stale_remaining(*args: object, **kwargs: object) -> int:
        return 100

    monkeypatch.setattr(users_service, "get_global_remaining", stale_remaining)

    results = await asyncio.gather(
        post_file(client, await bearer_for(anna), b"a" * 70, "a.txt"),
        post_file(client, await bearer_for(bob), b"b" * 70, "b.txt"),
    )
    assert sorted(r.status_code for r in results) == [201, 507]
    assert await count_files(db_sessionmaker) == 1
    assert len(blob_store.blobs) == 1  # the loser's blob was deleted again
