"""Blob storage: the in-memory fake and the Azure implementation.

The Azure tests here need no network: a stand-in replaces the SDK's container client, and the
SAS URL is signed locally. Tests against real Azure are in ``tests/integration/``.
"""

import base64
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

from app.errors import FileTooLarge, StorageUnavailable
from app.storage.azure_blob import (
    MAX_BLOCKS,
    AzureBlobStore,
    content_disposition,
    create_blob_store,
    parse_connection_string,
)
from tests.conftest import make_settings
from tests.fakes import InMemoryBlobStore, parse_download_url

pytestmark = pytest.mark.anyio

ACCOUNT_KEY = base64.b64encode(b"k" * 32).decode()
CONNECTION_STRING = (
    f"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={ACCOUNT_KEY};"
    "EndpointSuffix=core.windows.net"
)


async def stream(*chunks: bytes, then: Exception | None = None) -> AsyncIterator[bytes]:
    """An async iterator over ``chunks`` that optionally raises afterwards."""
    for chunk in chunks:
        yield chunk
    if then is not None:
        raise then


# --- The in-memory fake follows the protocol -----------------------------------------------------


async def test_fake_upload_stores_the_bytes_and_returns_the_size() -> None:
    store = InMemoryBlobStore()
    written = await store.upload_stream("b1", stream(b"ab", b"cde"), content_type="text/plain")
    assert written == 5
    assert store.blobs["b1"].data == b"abcde"
    assert store.blobs["b1"].content_type == "text/plain"


async def test_fake_aborted_upload_leaves_no_blob() -> None:
    """A stream that raises leaves no blob and the error propagates."""
    store = InMemoryBlobStore()
    with pytest.raises(FileTooLarge):
        await store.upload_stream("b1", stream(b"ab", then=FileTooLarge()), content_type="x/y")
    assert store.blobs == {}


async def test_fake_delete_is_idempotent() -> None:
    store = InMemoryBlobStore()
    store.put("b1", b"x")
    await store.delete("b1")
    await store.delete("b1")
    assert store.blobs == {} and store.deleted == ["b1", "b1"]


async def test_fake_download_url_encodes_its_parameters() -> None:
    store = InMemoryBlobStore()
    url = await store.download_url(
        "b1", filename="r é.pdf", content_type="application/pdf", ttl_seconds=300
    )
    assert parse_download_url(url) == {
        "blob": "b1",
        "filename": "r é.pdf",
        "content_type": "application/pdf",
        "ttl": "300",
        "sp": "r",
    }
    assert url.startswith("https://")


async def test_fake_unhealthy_store_raises_storage_unavailable() -> None:
    store = InMemoryBlobStore()
    store.healthy = False
    with pytest.raises(StorageUnavailable):
        await store.ping()
    with pytest.raises(StorageUnavailable):
        await store.delete("b1")
    with pytest.raises(StorageUnavailable):
        await store.upload_stream("b1", stream(b"x"), content_type="x/y")


async def test_fake_lists_only_old_blobs() -> None:
    store = InMemoryBlobStore()
    now = datetime.now(UTC)
    store.put("old", b"1", last_modified=now - timedelta(hours=30))
    store.put("new", b"2", last_modified=now)
    names = [b.name async for b in store.list_blobs(older_than=now - timedelta(hours=24))]
    assert names == ["old"]


# --- Azure implementation with a stand-in for the SDK --------------------------------------------


class FakeBlobClient:
    def __init__(self, name: str, container: "FakeContainer") -> None:
        self.url = f"https://acct.blob.core.windows.net/silo-test/{name}"
        self.container = container
        self.staged: list[tuple[str, bytes]] = []
        self.committed: list[list[str]] = []
        self.content_types: list[str] = []

    async def stage_block(self, block_id: str, data: bytes, length: int) -> None:
        self.container.raise_if_failing("stage")
        assert length == len(data)
        self.staged.append((block_id, data))

    async def commit_block_list(self, blocks: list[Any], content_settings: Any) -> None:
        self.container.raise_if_failing("commit")
        self.committed.append([block.id for block in blocks])
        self.content_types.append(content_settings.content_type)

    async def delete_blob(self) -> None:
        self.container.raise_if_failing("delete")


class FakeContainer:
    def __init__(self) -> None:
        self.clients: dict[str, FakeBlobClient] = {}
        self.failures: dict[str, Exception] = {}
        self.listing: list[Any] = []

    def raise_if_failing(self, operation: str) -> None:
        if operation in self.failures:
            raise self.failures[operation]

    def get_blob_client(self, name: str) -> FakeBlobClient:
        return self.clients.setdefault(name, FakeBlobClient(name, self))

    async def get_container_properties(self) -> None:
        self.raise_if_failing("ping")

    def list_blobs(self) -> AsyncIterator[Any]:
        async def generate() -> AsyncIterator[Any]:
            self.raise_if_failing("list")
            for blob in self.listing:
                yield blob

        return generate()


def make_store(block_bytes: int = 4) -> tuple[AzureBlobStore, FakeContainer]:
    container = FakeContainer()
    service = SimpleNamespace(get_container_client=lambda name: container)
    store = AzureBlobStore(
        service,  # type: ignore[arg-type]
        "silo-test",
        account_name="acct",
        account_key=ACCOUNT_KEY,
        block_bytes=block_bytes,
    )
    return store, container


async def test_azure_upload_collects_small_chunks_into_blocks() -> None:
    """Small chunks are joined into blocks, so a file never needs more than 50,000 blocks."""
    store, container = make_store(block_bytes=4)
    written = await store.upload_stream(
        "b1", stream(b"ab", b"cd", b"e", b"f", b"ghijkl"), content_type="text/plain"
    )
    blob = container.clients["b1"]
    assert written == 12
    assert b"".join(data for _, data in blob.staged) == b"abcdefghijkl"
    assert [data for _, data in blob.staged] == [b"abcd", b"efghijkl"]
    # Fixed-width block IDs (Azure requires equal lengths), committed in order, once.
    assert [block_id for block_id, _ in blob.staged] == ["00000000", "00000001"]
    assert blob.committed == [["00000000", "00000001"]]
    assert blob.content_types == ["text/plain"]


async def test_azure_empty_upload_commits_an_empty_blob() -> None:
    store, container = make_store()
    assert await store.upload_stream("b1", stream(b"", b""), content_type="x/y") == 0
    assert container.clients["b1"].committed == [[]]


async def test_azure_aborted_upload_never_commits() -> None:
    """If the chunks raise, nothing is committed and the original error propagates (s. 2.2)."""
    store, container = make_store()
    with pytest.raises(FileTooLarge):
        await store.upload_stream(
            "b1", stream(b"abcdef", b"gh", then=FileTooLarge()), content_type="x/y"
        )
    assert container.clients["b1"].committed == []


async def test_azure_errors_become_storage_unavailable() -> None:
    """SDK errors are re-raised as StorageUnavailable, chained to the cause."""
    store, container = make_store()
    container.failures["stage"] = HttpResponseError("boom")
    with pytest.raises(StorageUnavailable) as error:
        await store.upload_stream("b1", stream(b"abcdef"), content_type="x/y")
    assert isinstance(error.value.__cause__, HttpResponseError)
    assert container.clients["b1"].committed == []

    container.failures = {"commit": HttpResponseError("boom")}
    with pytest.raises(StorageUnavailable):
        await store.upload_stream("b2", stream(b"ab"), content_type="x/y")


async def test_azure_too_many_blocks_is_refused() -> None:
    store, container = make_store(block_bytes=1)
    blob = container.get_blob_client("b1")

    async def many() -> AsyncIterator[bytes]:
        for _ in range(MAX_BLOCKS + 1):
            yield b"x"

    with pytest.raises(StorageUnavailable):
        await store.upload_stream("b1", many(), content_type="x/y")
    assert blob.committed == []


async def test_azure_delete_is_idempotent_but_reports_real_errors() -> None:
    store, container = make_store()
    container.failures["delete"] = ResourceNotFoundError("gone")
    await store.delete("b1")  # a missing blob is fine
    container.failures["delete"] = HttpResponseError("boom")
    with pytest.raises(StorageUnavailable):
        await store.delete("b1")


async def test_azure_ping() -> None:
    store, container = make_store()
    await store.ping()
    container.failures["ping"] = ResourceNotFoundError("no such container")
    with pytest.raises(StorageUnavailable):
        await store.ping()


async def test_azure_lists_old_blobs_and_translates_errors() -> None:
    store, container = make_store()
    now = datetime.now(UTC)
    container.listing = [
        SimpleNamespace(name="old", size=3, last_modified=now - timedelta(hours=30)),
        SimpleNamespace(name="new", size=4, last_modified=now),
    ]
    found = [b async for b in store.list_blobs(older_than=now - timedelta(hours=24))]
    assert [(b.name, b.size) for b in found] == [("old", 3)]

    container.failures["list"] = HttpResponseError("boom")
    with pytest.raises(StorageUnavailable):
        _ = [b async for b in store.list_blobs(older_than=now)]


# --- SAS URLs (signed locally, no network) -------------------------------------------------------


def real_store() -> AzureBlobStore:
    settings = make_settings(
        azure_storage_connection_string=CONNECTION_STRING, azure_storage_container="silo-test"
    )
    return create_blob_store(settings)  # type: ignore[return-value]


async def test_sas_url_is_read_only_single_blob_https_and_short_lived() -> None:
    """Read-only, one blob, HTTPS only, expires after the TTL, forces download."""
    store = real_store()
    before = datetime.now(UTC)
    url = await store.download_url(
        "blob-1", filename="Résumé.pdf", content_type="application/pdf", ttl_seconds=300
    )
    parts = urlparse(url)
    query = {key: value[0] for key, value in parse_qs(parts.query).items()}

    assert parts.scheme == "https"
    assert parts.path == "/silo-test/blob-1"
    assert query["sp"] == "r"  # read only: no write, delete or list
    assert query["sr"] == "b"  # one blob, not the container
    assert query["spr"] == "https"
    assert "sig" in query
    expiry = datetime.strptime(query["se"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert timedelta(seconds=290) < expiry - before < timedelta(seconds=310)
    assert query["rsct"] == "application/pdf"
    assert query["rscd"].startswith("attachment;")
    assert "filename*=UTF-8''R%C3%A9sum%C3%A9.pdf" in query["rscd"]
    await store.close()


async def test_sas_ttl_must_be_positive() -> None:
    store = real_store()
    with pytest.raises(ValueError):
        await store.download_url("b", filename="a", content_type="x/y", ttl_seconds=0)
    await store.close()


@pytest.mark.parametrize(
    ("filename", "expected_fallback"),
    [
        ("report.pdf", "report.pdf"),
        ('a"b\\c.txt', "a_b_c.txt"),
        ("line\r\nbreak.txt", "linebreak.txt"),
        ("", "download"),
        ("日本.txt", "__.txt"),
    ],
)
def test_content_disposition_is_safe(filename: str, expected_fallback: str) -> None:
    """No header injection, no quote escape; the real name travels in filename* (RFC 5987)."""
    value = content_disposition(filename)
    assert value.startswith(f"attachment; filename=\"{expected_fallback}\"; filename*=UTF-8''")
    assert "\r" not in value and "\n" not in value


# --- Creating the store --------------------------------------------------------------------------


def test_connection_string_parsing_keeps_base64_padding() -> None:
    parts = parse_connection_string("AccountName=acct;AccountKey=abc==;EndpointSuffix=x")
    assert parts["AccountKey"] == "abc=="


@pytest.mark.parametrize(
    "value", ["UseDevelopmentStorage=true", "AccountName=acct", "AccountKey=abc", "garbage"]
)
def test_connection_string_without_account_key_is_refused(value: str) -> None:
    """SAS URLs need the account key, so startup refuses anything without it; no value shown."""
    settings = make_settings(azure_storage_connection_string=value)
    with pytest.raises(ValueError, match="AccountName and AccountKey") as error:
        create_blob_store(settings)
    assert value not in str(error.value)
