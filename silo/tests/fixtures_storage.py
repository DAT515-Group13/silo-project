"""Storage fixtures, loaded through ``pytest_plugins`` in ``tests/conftest.py`` (plan D7)."""

import pytest

from tests.fakes import InMemoryBlobStore


@pytest.fixture
def blob_store() -> InMemoryBlobStore:
    """The fake blob store injected into the app (a new, empty one for every test)."""
    return InMemoryBlobStore()
