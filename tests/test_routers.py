"""Pagination and ID parameters shared by the endpoints, and small router helpers."""

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import Request

from app.models import Role
from app.routers.common import client_ip, declared_size, page_count, utc_time
from app.routers.file_pages import _file_id_of
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


@pytest.mark.parametrize(("total", "pages"), [(0, 1), (1, 1), (25, 1), (26, 2), (50, 2)])
def test_page_count_rounds_up_and_is_at_least_one(total: int, pages: int) -> None:
    """An empty list is "page 1 of 1"; 26 rows at 25 per page are 2 pages."""
    assert page_count(total, 25) == pages


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        (("203.0.113.5", 1), "203.0.113.5"),
        (("2001:db8::1", 1), "2001:db8::1"),
        (("not-an-ip", 1), None),
        (None, None),
    ],
    ids=["ipv4", "ipv6", "not an address", "no client"],
)
def test_client_ip_keeps_only_real_addresses(
    client: tuple[str, int] | None, expected: str | None
) -> None:
    """The value goes into an ``inet`` column, so anything else becomes None instead of a 500."""
    assert client_ip(Request({"type": "http", "headers": [], "client": client})) == expected


@pytest.mark.parametrize(
    ("headers", "expected"),
    [([(b"content-length", b"12")], 12), ([(b"content-length", b"abc")], None), ([], None)],
    ids=["number", "not a number", "missing"],
)
def test_declared_size_is_only_a_hint(headers: list, expected: int | None) -> None:
    """A missing or false Content-Length is None, never an error."""
    assert declared_size(Request({"type": "http", "headers": headers})) == expected


def test_utc_time_shows_the_moment_in_utc() -> None:
    """A time from any zone is rendered in UTC; ``datetime`` carries the exact moment."""
    moment = datetime(2026, 1, 2, 4, 30, tzinfo=timezone(timedelta(hours=1)))
    assert str(utc_time(moment)) == (
        '<time datetime="2026-01-02T03:30:00+00:00" data-local>2026-01-02 03:30 UTC</time>'
    )


FILE_ID = uuid.uuid4()


@pytest.mark.parametrize(
    ("next_url", "expected"),
    [
        (f"/files/{FILE_ID}", FILE_ID),
        ("/files/not-a-uuid", None),
        (f"/files/{FILE_ID}/rename", None),
        ("/links", None),
        ("", None),
    ],
)
def test_return_address_of_a_file_page(next_url: str, expected: uuid.UUID | None) -> None:
    """Only ``/files/<id>`` is a file page; any other ``next`` falls back to the links overview."""
    assert _file_id_of(next_url) == expected
