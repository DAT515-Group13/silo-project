"""Orphan cleanup: delete blobs that no ``files`` row refers to (architecture.md section 10).

Orphans come from failures between storing a blob and committing its row, and from blob deletes
that failed after a file was deleted (D24). Only blobs older than ``MIN_AGE`` are considered, so
a blob whose upload transaction is still running is never deleted.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.errors import StorageUnavailable
from app.models import File, Outcome
from app.services import audit
from app.services.audit import AuditAction, AuditContext
from app.storage.base import BlobStore

logger = logging.getLogger("silo")

MIN_AGE = timedelta(hours=24)
# Blob names are looked up in the database this many at a time.
BATCH_SIZE = 500


@dataclass(frozen=True)
class CleanupResult:
    """How many old blobs were looked at and how many were (or, in a dry run, would be) deleted."""

    scanned: int
    deleted: int


async def _referenced(session: AsyncSession, names: list[str]) -> set[str]:
    """The names among ``names`` that a ``files`` row points to."""
    async with session.begin():
        rows = await session.scalars(select(File.blob_name).where(File.blob_name.in_(names)))
        return set(rows)


async def cleanup_orphans(
    session: AsyncSession,
    store: BlobStore,
    *,
    dry_run: bool = False,
    now: datetime | None = None,
) -> CleanupResult:
    """Delete the unreferenced blobs older than 24 hours.

    With ``dry_run`` nothing is deleted and nothing is audited. Otherwise one
    ``storage.orphan_cleanup`` entry (actor ``system``) records ``scanned`` and ``deleted``; if
    storage fails halfway, the entry has outcome ``failed`` with the counts so far, and the
    ``StorageUnavailable`` is raised after it is written.

    Raises:
        StorageUnavailable: listing or deleting failed.
    """
    cutoff = (now or datetime.now(UTC)) - MIN_AGE
    counts = {"scanned": 0, "deleted": 0}
    failure: StorageUnavailable | None = None

    async def process(batch: list[str]) -> None:
        referenced = await _referenced(session, batch)
        for name in batch:
            if name in referenced:
                continue
            if not dry_run:
                await store.delete(name)
            counts["deleted"] += 1

    try:
        batch: list[str] = []
        async for blob in store.list_blobs(older_than=cutoff):
            counts["scanned"] += 1
            batch.append(blob.name)
            if len(batch) >= BATCH_SIZE:
                await process(batch)
                batch = []
        if batch:
            await process(batch)
    except StorageUnavailable as exc:
        failure = exc

    if not dry_run:
        async with session.begin():
            await audit.record(
                session,
                AuditContext.system(),
                AuditAction.storage_orphan_cleanup,
                outcome=Outcome.failed if failure else Outcome.success,
                details=dict(counts),
            )
    if failure is not None:
        raise failure
    logger.info("Orphan cleanup: %s (dry run: %s)", counts, dry_run)
    return CleanupResult(**counts)
