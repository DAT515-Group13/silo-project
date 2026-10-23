"""Azure Blob Storage against the real service.

Run with ``pytest -m azure`` and ``AZURE_STORAGE_CONNECTION_STRING`` plus
``AZURE_STORAGE_CONTAINER`` set (a dedicated test container). Without them every test is skipped.
"""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.errors import FileTooLarge, StorageUnavailable
from app.storage.azure_blob import create_blob_store
from app.storage.base import BlobStore
from tests.conftest import make_settings

pytestmark = pytest.mark.anyio

PAYLOAD = bytes(range(256)) * 20  # 5,120 bytes: five 1 KiB blocks


async def stream(*chunks: bytes, then: Exception | None = None) -> AsyncIterator[bytes]:
    for chunk in chunks:
        yield chunk
    if then is not None:
        raise then


async def exists(url: str) -> bool:
    async with httpx.AsyncClient() as client:
        return (await client.get(url)).status_code == 200


async def test_ping_succeeds_for_the_configured_container(azure_store: BlobStore) -> None:
    await azure_store.ping()


async def test_ping_fails_for_a_missing_container(azure_settings: dict[str, str]) -> None:
    """A wrong container name is 503 on /readyz (phase 0)."""
    settings = make_settings(
        **{**azure_settings, "azure_storage_container": f"no-such-{os.urandom(4).hex()}"}
    )
    store = create_blob_store(settings)
    try:
        with pytest.raises(StorageUnavailable):
            await store.ping()
    finally:
        await store.close()


async def test_upload_then_download_through_the_sas_url(
    azure_store: BlobStore, blob_name: str
) -> None:
    """Upload several blocks, download via SAS: same bytes, attachment, overridden type."""
    written = await azure_store.upload_stream(
        blob_name,
        stream(*(PAYLOAD[i : i + 700] for i in range(0, len(PAYLOAD), 700))),
        content_type="application/octet-stream",
    )
    assert written == len(PAYLOAD)

    url = await azure_store.download_url(
        blob_name, filename="Résumé 1.pdf", content_type="text/plain", ttl_seconds=120
    )
    assert url.startswith("https://")
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
    assert response.status_code == 200
    assert response.content == PAYLOAD
    assert response.headers["content-disposition"].startswith("attachment;")
    assert "R%C3%A9sum%C3%A9%201.pdf" in response.headers["content-disposition"]
    assert response.headers["content-type"].startswith("text/plain")  # the override


async def test_empty_upload_creates_an_empty_blob(azure_store: BlobStore, blob_name: str) -> None:
    assert await azure_store.upload_stream(blob_name, stream(), content_type="text/plain") == 0
    url = await azure_store.download_url(
        blob_name, filename="empty.txt", content_type="text/plain", ttl_seconds=60
    )
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
    assert (response.status_code, response.content) == (200, b"")


async def test_aborted_upload_leaves_no_blob(azure_store: BlobStore, blob_name: str) -> None:
    """A stream that raises after some blocks must not create a visible blob."""
    with pytest.raises(FileTooLarge):
        await azure_store.upload_stream(
            blob_name, stream(PAYLOAD, then=FileTooLarge()), content_type="x/y"
        )
    url = await azure_store.download_url(
        blob_name, filename="a", content_type="x/y", ttl_seconds=60
    )
    assert not await exists(url)


async def test_sas_url_cannot_write_or_list(azure_store: BlobStore, blob_name: str) -> None:
    """The SAS grants reading one blob only."""
    await azure_store.upload_stream(blob_name, stream(b"data"), content_type="x/y")
    url = await azure_store.download_url(
        blob_name, filename="a", content_type="x/y", ttl_seconds=60
    )
    base, query = url.split("?", 1)
    container_url = base.rsplit("/", 1)[0]
    async with httpx.AsyncClient() as client:
        write = await client.put(url, content=b"x", headers={"x-ms-blob-type": "BlockBlob"})
        listing = await client.get(f"{container_url}?restype=container&comp=list&{query}")
        removal = await client.delete(url)
    assert write.status_code in (401, 403)
    assert listing.status_code in (401, 403)
    assert removal.status_code in (401, 403)


async def test_delete_is_idempotent(azure_store: BlobStore, blob_name: str) -> None:
    await azure_store.upload_stream(blob_name, stream(b"data"), content_type="x/y")
    await azure_store.delete(blob_name)
    await azure_store.delete(blob_name)
    url = await azure_store.download_url(
        blob_name, filename="a", content_type="x/y", ttl_seconds=60
    )
    assert not await exists(url)


async def test_list_blobs_finds_old_enough_blobs_only(
    azure_store: BlobStore, blob_name: str
) -> None:
    """Orphan cleanup lists blobs older than a cut-off."""
    await azure_store.upload_stream(blob_name, stream(b"data"), content_type="x/y")
    now = datetime.now(UTC)
    recent = [b.name async for b in azure_store.list_blobs(older_than=now - timedelta(hours=24))]
    later = [b.name async for b in azure_store.list_blobs(older_than=now + timedelta(minutes=5))]
    assert blob_name not in recent
    assert blob_name in later
