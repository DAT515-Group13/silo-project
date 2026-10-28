"""Pagination and ID parameters shared by the endpoints."""

import httpx
import pytest

from app.models import Role
from tests.conftest import ActAs


@pytest.mark.anyio
@pytest.mark.parametrize("query", ["page=0", "page=1000001", "size=0", "size=101"])
async def test_pagination_bounds(client: httpx.AsyncClient, act_as: ActAs, query: str) -> None:
    """1 <= page <= 1,000,000 and 1 <= size <= 100; violations are 422 validation_error.

    All list endpoints share one parameter definition, so one of them stands for all. The
    parameters are checked before the service runs, so no database is needed.
    """
    act_as(Role.admin)
    response = await client.get(f"/api/v1/admin/users?{query}")
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "path",
    ["/api/v1/teams/0", "/api/v1/teams/99999999999", "/api/v1/admin/audit?actor_id=99999999999"],
)
async def test_ids_outside_the_database_range_are_422(
    client: httpx.AsyncClient, act_as: ActAs, path: str
) -> None:
    """IDs are 32-bit integers; a bigger one is refused before it reaches the driver (no 500)."""
    act_as(Role.admin)
    response = await client.get(path)
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


@pytest.mark.anyio
async def test_sort_and_scope_are_validated(client: httpx.AsyncClient, act_as: ActAs) -> None:
    """Unknown sort keys and scopes are refused, so no column name reaches the database."""
    act_as(Role.user)
    assert (await client.get("/api/v1/files", params={"sort": "owner_id"})).status_code == 422
    assert (await client.get("/api/v1/files", params={"scope": "all"})).status_code == 422
