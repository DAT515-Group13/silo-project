"""The admin command ``python -m app.cli cleanup-orphans`` (the scheduled cleanup job).

The cleanup itself is replaced here, its rules are tested in ``test_orphans.py``. The engine is
created but never connected, so no database is needed. These tests check what the job runner
sees: the exit code, the output and that the blob store is closed in every case.
"""

import pytest

from app import cli
from app.errors import StorageUnavailable
from app.services.orphans import CleanupResult
from tests.conftest import make_settings
from tests.fakes import InMemoryBlobStore


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> InMemoryBlobStore:
    """Run the command with test settings and a fake blob store, returned to check ``closed``."""
    fake = InMemoryBlobStore()
    monkeypatch.setattr(cli, "get_settings", make_settings)
    monkeypatch.setattr(cli, "create_blob_store", lambda settings: fake)
    return fake


@pytest.mark.parametrize(("flags", "verb"), [(["--dry-run"], "would delete"), ([], "deleted")])
def test_cleanup_prints_the_counts_and_exits_0(
    store: InMemoryBlobStore,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    flags: list[str],
    verb: str,
) -> None:
    """--dry-run reaches the cleanup; the output has counts only and the exit code is 0."""
    dry_runs: list[bool] = []

    async def cleanup(session: object, blob_store: object, *, dry_run: bool) -> CleanupResult:
        dry_runs.append(dry_run)
        return CleanupResult(scanned=3, deleted=1)

    monkeypatch.setattr(cli, "cleanup_orphans", cleanup)
    assert cli.main(["cleanup-orphans", *flags]) == 0
    assert dry_runs == [bool(flags)]
    assert capsys.readouterr().out == f"Scanned 3 old blobs, {verb} 1 orphans.\n"
    assert store.closed


def test_storage_outage_exits_1_and_still_closes_the_store(
    store: InMemoryBlobStore,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed run exits 1 with a short message, so the CronJob shows it as failed."""

    async def cleanup(*args: object, **kwargs: object) -> CleanupResult:
        raise StorageUnavailable

    monkeypatch.setattr(cli, "cleanup_orphans", cleanup)
    assert cli.main(["cleanup-orphans"]) == 1
    assert "Blob storage is unavailable" in capsys.readouterr().err
    assert store.closed
