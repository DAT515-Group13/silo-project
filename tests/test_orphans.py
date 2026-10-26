"""Orphan cleanup (architecture.md sections 10 and 16): only unreferenced blobs older than 24 h.

The service runs against a stand-in session whose database lookup is replaced, so the rules are
tested without PostgreSQL; one ``db`` test checks the real lookup.
"""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.errors import StorageUnavailable
from app.models import ActorType, AuditLog, Outcome
from app.services import orphans
from app.services.orphans import cleanup_orphans
from tests.conftest import FileFactory, Sessionmaker, UserFactory
from tests.fakes import InMemoryBlobStore

pytestmark = pytest.mark.anyio

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


class FakeSession:
    """Just enough of an AsyncSession for the audit entry: begin, add, flush."""

    def __init__(self) -> None:
        self.added: list[AuditLog] = []

    @asynccontextmanager
    async def begin(self):  # noqa: ANN201
        yield

    def add(self, row: AuditLog) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        return None


@pytest.fixture
def referenced(monkeypatch: pytest.MonkeyPatch) -> set[str]:
    """The blob names the (replaced) database lookup reports as used; the test fills it."""
    names: set[str] = set()

    async def fake_referenced(session: object, batch: list[str]) -> set[str]:
        return names & set(batch)

    monkeypatch.setattr(orphans, "_referenced", fake_referenced)
    return names


def stocked_store() -> InMemoryBlobStore:
    store = InMemoryBlobStore()
    store.put("old-used", b"1", last_modified=NOW - timedelta(hours=30))
    store.put("old-orphan", b"2", last_modified=NOW - timedelta(hours=30))
    store.put("new-orphan", b"3", last_modified=NOW - timedelta(hours=23))  # upload may be running
    return store


async def test_only_old_unreferenced_blobs_are_deleted(referenced: set[str]) -> None:
    """A used blob and a blob younger than 24 hours stay; the old orphan goes."""
    referenced.add("old-used")
    store, session = stocked_store(), FakeSession()
    result = await cleanup_orphans(session, store, now=NOW)  # type: ignore[arg-type]
    assert (result.scanned, result.deleted) == (2, 1)
    assert set(store.blobs) == {"old-used", "new-orphan"}


async def test_cleanup_writes_one_system_audit_entry(referenced: set[str]) -> None:
    """Actor system, with the counts in the details (section 10)."""
    store, session = stocked_store(), FakeSession()
    await cleanup_orphans(session, store, now=NOW)  # type: ignore[arg-type]
    (entry,) = session.added
    assert entry.action == "storage.orphan_cleanup"
    assert (entry.actor_type, entry.outcome) == (ActorType.system, Outcome.success)
    assert entry.details == {"scanned": 2, "deleted": 2}


async def test_dry_run_changes_and_audits_nothing(referenced: set[str]) -> None:
    """--dry-run counts what would go but deletes nothing and writes no audit entry."""
    store, session = stocked_store(), FakeSession()
    result = await cleanup_orphans(session, store, dry_run=True, now=NOW)  # type: ignore[arg-type]
    assert (result.scanned, result.deleted) == (2, 2)
    assert len(store.blobs) == 3
    assert session.added == []


async def test_a_storage_failure_is_audited_as_failed_then_raised(
    referenced: set[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counts so far are kept in a `failed` entry, so a half-done run is visible."""
    store, session = stocked_store(), FakeSession()

    async def broken_delete(name: str) -> None:
        raise StorageUnavailable

    monkeypatch.setattr(store, "delete", broken_delete)
    with pytest.raises(StorageUnavailable):
        await cleanup_orphans(session, store, now=NOW)  # type: ignore[arg-type]
    (entry,) = session.added
    assert entry.outcome == Outcome.failed
    assert entry.details == {"scanned": 2, "deleted": 0}


async def test_many_blobs_are_checked_in_batches(
    referenced: set[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """More blobs than one batch are all handled (and the lookup is called per batch)."""
    monkeypatch.setattr(orphans, "BATCH_SIZE", 2)
    store = InMemoryBlobStore()
    for number in range(5):
        store.put(f"old-{number}", b"x", last_modified=NOW - timedelta(days=2))
    referenced.add("old-3")
    result = await cleanup_orphans(FakeSession(), store, now=NOW)  # type: ignore[arg-type]
    assert (result.scanned, result.deleted) == (5, 4)
    assert set(store.blobs) == {"old-3"}


def test_cli_requires_a_command(capsys: pytest.CaptureFixture[str]) -> None:
    """`python -m app.cli` without a command prints usage and exits with an error."""
    from app.cli import main

    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2


@pytest.mark.db
async def test_real_lookup_keeps_blobs_of_existing_files(
    db_sessionmaker: Sessionmaker, user_factory: UserFactory, file_factory: FileFactory
) -> None:
    """Against PostgreSQL: a blob with a files row survives, an unknown old blob is removed."""
    owner = await user_factory("owner")
    used = await file_factory(owner.id)
    store = InMemoryBlobStore()
    old = datetime.now(UTC) - timedelta(days=2)
    store.put(used.blob_name, b"x", last_modified=old)
    store.put("stray", b"y", last_modified=old)

    async with db_sessionmaker() as session:
        result = await cleanup_orphans(session, store)
    assert (result.scanned, result.deleted) == (2, 1)
    assert set(store.blobs) == {used.blob_name}
    async with db_sessionmaker() as session:
        entry = (await session.scalars(select(AuditLog))).one()
    assert entry.action == "storage.orphan_cleanup" and entry.actor_id is None
