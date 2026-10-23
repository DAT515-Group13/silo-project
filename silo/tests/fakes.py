"""In-memory ``BlobStore`` for tests.

It follows the protocol exactly: an upload stream that raises leaves no blob, ``delete`` is
idempotent, and ``download_url`` returns a fake URL that encodes its parameters so tests can
assert on them (``parse_download_url``). Switching ``healthy`` to False makes every operation
raise ``StorageUnavailable``, like an Azure outage.
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qs, quote, urlencode, urlparse

from app.errors import StorageUnavailable
from app.storage.base import BlobInfo

FAKE_HOST = "https://fake-blob.test"


@dataclass
class StoredBlob:
    """What the fake keeps per blob."""

    data: bytes
    content_type: str
    last_modified: datetime


class InMemoryBlobStore:
    """A ``BlobStore`` that keeps blobs in a dict."""

    def __init__(self, container: str = "silo-test") -> None:
        self.container = container
        self.blobs: dict[str, StoredBlob] = {}
        self.healthy = True
        self.closed = False
        self.deleted: list[str] = []  # names passed to delete(), in order

    def _check(self) -> None:
        if not self.healthy:
            raise StorageUnavailable

    def put(
        self,
        name: str,
        data: bytes = b"",
        *,
        content_type: str = "application/octet-stream",
        last_modified: datetime | None = None,
    ) -> None:
        """Add a blob directly (set-up helper for tests, for example an old orphan)."""
        self.blobs[name] = StoredBlob(data, content_type, last_modified or datetime.now(UTC))

    async def upload_stream(
        self, blob_name: str, chunks: AsyncIterator[bytes], *, content_type: str
    ) -> int:
        """Collect the chunks; the blob exists only after the last one."""
        self._check()
        buffer = bytearray()
        # If `chunks` raises, the exception propagates and nothing was stored.
        async for chunk in chunks:
            buffer += chunk
        self._check()
        self.put(blob_name, bytes(buffer), content_type=content_type)
        return len(buffer)

    async def delete(self, blob_name: str) -> None:
        """Remove a blob if it exists; always records the call."""
        self._check()
        self.deleted.append(blob_name)
        self.blobs.pop(blob_name, None)

    async def download_url(
        self, blob_name: str, *, filename: str, content_type: str, ttl_seconds: int
    ) -> str:
        """Return ``https://fake-blob.test/<container>/<blob>?filename=...&ttl=...``."""
        self._check()
        query = urlencode(
            {"filename": filename, "content_type": content_type, "ttl": ttl_seconds, "sp": "r"}
        )
        return f"{FAKE_HOST}/{self.container}/{quote(blob_name)}?{query}"

    async def ping(self) -> None:
        """Succeed unless the store is switched to unhealthy."""
        self._check()

    async def list_blobs(self, *, older_than: datetime) -> AsyncIterator[BlobInfo]:
        """Yield blobs last modified before ``older_than``, oldest first."""
        self._check()
        for name, blob in sorted(self.blobs.items(), key=lambda item: item[1].last_modified):
            if blob.last_modified < older_than:
                yield BlobInfo(name=name, size=len(blob.data), last_modified=blob.last_modified)

    async def close(self) -> None:
        """Remember that the store was closed."""
        self.closed = True


def parse_download_url(url: str) -> dict[str, str]:
    """Split a fake download URL into ``blob``, ``filename``, ``content_type``, ``ttl``, ``sp``."""
    parts = urlparse(url)
    assert f"{parts.scheme}://{parts.netloc}" == FAKE_HOST, url
    values = {key: value[0] for key, value in parse_qs(parts.query).items()}
    values["blob"] = parts.path.rsplit("/", 1)[-1]
    return values
