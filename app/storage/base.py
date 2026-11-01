"""The ``BlobStore`` protocol: all blob access goes through it.

Services never use a storage SDK directly, so the backend (Azure today) can be swapped without
changing them. A store knows nothing about users, quotas or permissions: the upload service
enforces size and quota limits, and decides who may download.

Every backend error is re-raised as ``StorageUnavailable`` (chained, never with secrets in the
message).
"""

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

logger = logging.getLogger("silo")


@dataclass(frozen=True)
class BlobInfo:
    """One blob as listed for orphan cleanup."""

    name: str
    size: int
    last_modified: datetime


class BlobStore(Protocol):
    """Operations the app needs from blob storage."""

    async def upload_stream(
        self, blob_name: str, chunks: AsyncIterator[bytes], *, content_type: str
    ) -> int:
        """Store the chunks as one blob and return the number of bytes written.

        The blob becomes visible only after the last chunk. If ``chunks`` raises (size limit,
        quota, client disconnect), no blob exists afterwards and that exception propagates
        unchanged. Backend errors become ``StorageUnavailable``.
        """
        ...

    async def delete(self, blob_name: str) -> None:
        """Delete a blob. Idempotent: a missing blob is not an error."""
        ...

    async def download_url(
        self, blob_name: str, *, filename: str, content_type: str, ttl_seconds: int
    ) -> str:
        """Return a short-lived, read-only, HTTPS-only URL for this one blob.

        Opening it downloads the file as an attachment named ``filename`` (RFC 5987 encoded)
        with the response content type ``content_type``. The URL is a secret: never store or
        log it.
        """
        ...

    async def ping(self) -> None:
        """Check that the configured container is reachable; raise ``StorageUnavailable``."""
        ...

    def list_blobs(self, *, older_than: datetime) -> AsyncIterator[BlobInfo]:
        """Iterate over blobs last modified before ``older_than`` (an aware UTC datetime)."""
        ...

    async def close(self) -> None:
        """Release the connection to the backend (called once at shutdown)."""
        ...


async def delete_quietly(store: BlobStore, blob_name: str) -> None:
    """Delete a blob, logging instead of raising: the caller's own error must not be masked.

    A blob that could not be deleted stays behind as an orphan; orphan cleanup removes it later.
    """
    try:
        await store.delete(blob_name)
    except Exception as exc:
        # Not only StorageUnavailable: when this runs after the commit, any error here must not
        # turn a finished delete into a 500.
        logger.warning(
            "Could not delete blob %s (%s); it is left for orphan cleanup",
            blob_name,
            type(exc).__name__,
        )
