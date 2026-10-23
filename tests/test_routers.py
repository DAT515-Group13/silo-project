"""Router registration and shared dependencies."""

import httpx
import pytest

from app.models import Role
from tests.conftest import ActAs

BEARER = {"Authorization": "Bearer anything"}


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/files"),
        ("POST", "/api/v1/files"),
        ("GET", "/api/v1/files/7f3a1c2e-5b9d-4e8a-9c41-2d6f0b8a1e33/links"),
        ("DELETE", "/api/v1/links/1"),
    ],
)
async def test_routes_owned_by_b_do_not_exist_yet(
    client: httpx.AsyncClient, method: str, path: str
) -> None:
    """B's routers are empty modules, so their paths answer 404 until B implements them."""
    response = await client.request(method, path, headers=BEARER)
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


@pytest.mark.anyio
async def test_public_link_route_does_not_exist_yet(client: httpx.AsyncClient) -> None:
    """/s/{token} belongs to B; until then it is a 404 page (not under /api/, so HTML)."""
    response = await client.get("/s/sometoken")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.anyio
async def test_missing_bearer_token_is_invalid_token(client: httpx.AsyncClient) -> None:
    """No Authorization header gives 401 invalid_token with WWW-Authenticate."""
    response = await client.get("/api/v1/teams")
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.anyio
async def test_cookie_is_not_accepted_on_the_api(client: httpx.AsyncClient) -> None:
    """Cookies are never accepted on /api/v1."""
    client.cookies.set("access_token", "x")
    response = await client.get("/api/v1/teams")
    assert response.status_code == 401


@pytest.mark.anyio
@pytest.mark.parametrize(
    "path", ["/api/v1/teams/1/files", "/api/v1/admin/users", "/api/v1/admin/files"]
)
@pytest.mark.parametrize("query", ["page=0", "size=0", "size=101"])
async def test_pagination_bounds(
    client: httpx.AsyncClient, act_as: ActAs, path: str, query: str
) -> None:
    """page >= 1 and 1 <= size <= 100; violations are 422 validation_error.

    The parameters are checked before the service runs, so no database is needed.
    """
    act_as(Role.admin)
    response = await client.get(f"{path}?{query}")
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"
