"""Security response headers (architecture.md section 12)."""

import httpx
import pytest

from tests.conftest import assert_secure

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("path", ["/login", "/healthz", "/api/v1/me", "/no-such-page"])
async def test_every_response_has_the_headers_and_is_not_cached(
    client: httpx.AsyncClient, path: str
) -> None:
    """Pages, API answers, errors and probes all carry the headers and Cache-Control: no-store."""
    response = await client.get(path)
    assert_secure(response)
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


async def test_static_files_stay_cacheable_but_get_the_other_headers(
    client: httpx.AsyncClient,
) -> None:
    """Bootstrap is served from /static (so the CSP can stay 'self') and may be cached."""
    response = await client.get("/static/bootstrap.min.css")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert "Bootstrap" in response.text[:200]
    assert response.headers.get("cache-control") != "no-store"
    assert_secure(response)
