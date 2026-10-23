"""Azure Blob Storage implementation of ``BlobStore``.

Uploads use block blobs: chunks are staged as blocks and committed with one call after the last
chunk, so a failed or aborted upload never creates a visible blob (uncommitted blocks are
invisible and Azure removes them after a week). Downloads are SAS URLs signed locally with the
account key from the connection string; no request to Azure is needed to create one.

Security rules kept here: the container is private and never changed by the app; SAS URLs are
read-only, for one blob, HTTPS-only and short-lived; SAS URLs, the connection string and the
account key are never logged. Every SDK error becomes ``StorageUnavailable``.
"""

import asyncio
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import aiohttp
from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.storage.blob import BlobBlock, BlobSasPermissions, ContentSettings, generate_blob_sas
from azure.storage.blob.aio import BlobServiceClient

from app.config import Settings
from app.errors import StorageUnavailable
from app.storage.base import BlobInfo, BlobStore

logger = logging.getLogger("silo")

# Azure allows at most 50,000 blocks per blob.
MAX_BLOCKS = 50_000
# /readyz must answer quickly even when Azure does not (the SDK retries on its own otherwise).
PING_TIMEOUT_SECONDS = 10
# Allowed clock difference between this server and Azure for the start of the SAS validity.
SAS_CLOCK_SKEW = timedelta(minutes=1)


@contextmanager
def _translate() -> Iterator[None]:
    """Turn every storage SDK or network error into ``StorageUnavailable``.

    Wrap only calls into the SDK, never the caller's data (for example the upload chunks): errors
    raised by the caller must propagate unchanged.
    """
    try:
        yield
    except (AzureError, aiohttp.ClientError, TimeoutError, OSError) as exc:
        # `from exc` keeps the cause for debugging. The SDK messages contain the request ID and
        # the account name, never the account key or a SAS signature.
        raise StorageUnavailable from exc


def parse_connection_string(connection_string: str) -> dict[str, str]:
    """Split ``Key=Value;Key=Value`` into a dict. Values may contain ``=`` (base64 padding)."""
    parts = (item.split("=", 1) for item in connection_string.split(";") if "=" in item)
    return {key.strip(): value.strip() for key, value in parts}


def content_disposition(filename: str) -> str:
    """Build the ``Content-Disposition`` value that forces a download (RFC 6266, RFC 5987).

    ``filename`` is the ASCII fallback for old clients, ``filename*`` carries the real name as
    percent-encoded UTF-8. Control characters (header injection) are removed, quotes and
    backslashes cannot end the quoted string.
    """
    cleaned = "".join(ch for ch in filename if ch >= " " and ch != "\x7f") or "download"
    fallback = cleaned.encode("ascii", "replace").decode("ascii")
    fallback = fallback.replace("?", "_").replace('"', "_").replace("\\", "_")
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(cleaned, safe='')}"


class AzureBlobStore:
    """``BlobStore`` backed by one private Azure container."""

    def __init__(
        self,
        service: BlobServiceClient,
        container: str,
        *,
        account_name: str,
        account_key: str,
        block_bytes: int,
    ) -> None:
        """Wrap an (unconnected) service client; ``create_blob_store`` is the normal way in.

        ``block_bytes`` is the size of the blocks written to Azure: small chunks from a slow
        client are collected up to this size, so a file never needs more than 50,000 blocks.
        """
        self._service = service
        self._container_name = container
        self._container = service.get_container_client(container)
        self._account_name = account_name
        self._account_key = account_key
        self._block_bytes = block_bytes

    async def upload_stream(
        self, blob_name: str, chunks: AsyncIterator[bytes], *, content_type: str
    ) -> int:
        """Stage the chunks as blocks and commit them after the last one (upload step 2)."""
        blob = self._container.get_blob_client(blob_name)
        block_ids: list[str] = []
        pending: list[bytes] = []
        pending_size = 0
        total = 0

        async def stage(data: bytes) -> None:
            if len(block_ids) >= MAX_BLOCKS:
                raise StorageUnavailable  # only reachable with a tiny UPLOAD_CHUNK_BYTES
            # Fixed-width IDs: Azure requires all block IDs of a blob to have the same length.
            # (The SDK base64-encodes the ID itself.)
            block_id = f"{len(block_ids):08d}"
            with _translate():
                await blob.stage_block(block_id, data, length=len(data))
            block_ids.append(block_id)

        # The loop header is outside `_translate`: an exception from `chunks` (size limit,
        # quota, client disconnect) propagates unchanged, and nothing has been committed yet.
        async for chunk in chunks:
            if not chunk:
                continue
            total += len(chunk)
            pending.append(chunk)
            pending_size += len(chunk)
            if pending_size >= self._block_bytes:
                await stage(b"".join(pending))
                pending, pending_size = [], 0
        if pending:
            await stage(b"".join(pending))

        # Only now does the blob appear. An empty upload commits an empty block list, which
        # creates an empty blob.
        with _translate():
            await blob.commit_block_list(
                [BlobBlock(block_id=block_id) for block_id in block_ids],
                content_settings=ContentSettings(content_type=content_type),
            )
        return total

    async def delete(self, blob_name: str) -> None:
        """Delete a blob; a missing blob is fine (idempotent)."""
        blob = self._container.get_blob_client(blob_name)
        try:
            with _translate():
                await blob.delete_blob()
        except StorageUnavailable as exc:
            if isinstance(exc.__cause__, ResourceNotFoundError):
                return
            raise

    async def download_url(
        self, blob_name: str, *, filename: str, content_type: str, ttl_seconds: int
    ) -> str:
        """Sign a read-only, HTTPS-only SAS URL for this blob.

        Signed locally, so it needs no request to Azure and cannot fail because of the network.
        The URL is never logged or stored.
        """
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        now = datetime.now(UTC)
        sas = generate_blob_sas(
            account_name=self._account_name,
            container_name=self._container_name,
            blob_name=blob_name,
            account_key=self._account_key,
            permission=BlobSasPermissions(read=True),  # no write, delete or list
            start=now - SAS_CLOCK_SKEW,
            expiry=now + timedelta(seconds=ttl_seconds),
            protocol="https",
            content_disposition=content_disposition(filename),
            content_type=content_type,
        )
        return f"{self._container.get_blob_client(blob_name).url}?{sas}"

    async def ping(self) -> None:
        """Check that the configured container exists and the key works (``/readyz``)."""
        with _translate():
            async with asyncio.timeout(PING_TIMEOUT_SECONDS):
                await self._container.get_container_properties()

    async def list_blobs(self, *, older_than: datetime) -> AsyncIterator[BlobInfo]:
        """Yield blobs last modified before ``older_than`` (orphan cleanup)."""
        iterator = self._container.list_blobs().__aiter__()
        while True:
            # Only the SDK call is translated, not the consumer's code between two items.
            with _translate():
                try:
                    blob: Any = await iterator.__anext__()
                except StopAsyncIteration:
                    return
            if blob.last_modified < older_than:
                yield BlobInfo(name=blob.name, size=blob.size, last_modified=blob.last_modified)

    async def close(self) -> None:
        """Close the HTTP session. Never raises: this runs during shutdown."""
        try:
            await self._service.close()
        except Exception as exc:
            logger.warning("Closing blob storage failed (%s)", type(exc).__name__)


def create_blob_store(settings: Settings) -> BlobStore:
    """Create the Azure store from the settings. Called once by the app lifespan.

    Does not connect: the first request does. A connection string without account name and key
    is refused at startup, because SAS URLs cannot be signed without the key.

    Raises:
        ValueError: if the connection string is malformed or has no account key. The message
            never contains the value.
    """
    connection_string = settings.azure_storage_connection_string.get_secret_value()
    parts = parse_connection_string(connection_string)
    account_name, account_key = parts.get("AccountName"), parts.get("AccountKey")
    if not account_name or not account_key:
        raise ValueError("AZURE_STORAGE_CONNECTION_STRING must contain AccountName and AccountKey.")
    try:
        # Timeouts: connecting 10 s, one read 60 s (one block of UPLOAD_CHUNK_BYTES).
        service = BlobServiceClient.from_connection_string(
            connection_string, connection_timeout=10, read_timeout=60
        )
    except ValueError:
        # `from None`: do not chain the SDK's error, to be sure no part of the value is shown.
        raise ValueError(
            "AZURE_STORAGE_CONNECTION_STRING is not a valid connection string."
        ) from None
    return AzureBlobStore(
        service,
        settings.azure_storage_container,
        account_name=account_name,
        account_key=account_key,
        block_bytes=settings.upload_chunk_bytes,
    )
