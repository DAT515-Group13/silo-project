"""Fixtures for the tests against real Azure Blob Storage.

They are marked ``azure`` and skipped unless ``AZURE_STORAGE_CONNECTION_STRING`` and
``AZURE_STORAGE_CONTAINER`` are set. Use a dedicated test container, never ``silo-prod``: every
blob the tests create is removed again, but the container is real.
"""

import os
import uuid
from collections.abc import AsyncIterator

import pytest

from app.storage.azure_blob import create_blob_store
from app.storage.base import BlobStore
from tests.conftest import make_settings


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark everything in this directory ``azure``, so ``-m azure`` selects it."""
    for item in items:
        if "tests/integration/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.azure)


@pytest.fixture
def azure_settings() -> dict[str, str]:
    """The Azure settings from the environment, or skip the test."""
    connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    container = os.environ.get("AZURE_STORAGE_CONTAINER")
    if not connection_string or not container:
        pytest.skip("AZURE_STORAGE_CONNECTION_STRING and AZURE_STORAGE_CONTAINER are not set")
    return {
        "azure_storage_connection_string": connection_string,
        "azure_storage_container": container,
    }


@pytest.fixture
async def azure_store(azure_settings: dict[str, str]) -> AsyncIterator[BlobStore]:
    """The real store, with a small block size so uploads use several blocks."""
    store = create_blob_store(make_settings(upload_chunk_bytes=1024, **azure_settings))
    yield store
    await store.close()


@pytest.fixture
async def blob_name(azure_store: BlobStore) -> AsyncIterator[str]:
    """A random blob name; the blob is deleted after the test, whatever happened."""
    name = f"it-{uuid.uuid4().hex}"
    yield name
    await azure_store.delete(name)
