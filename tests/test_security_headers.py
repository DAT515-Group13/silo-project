"""Security response headers (architecture.md section 12)."""

import httpx
import pytest

from app.main import create_app
from app.middleware import SECURITY_HEADERS
from tests.conftest import make_settings
from tests.fakes import InMemoryBlobStore

pytestmark = pytest.mark.anyio


def assert_secure(response: httpx.Response, *, csp: bool = True) -> None:
    for name, value in SECURITY_HEADERS.items():
        if name == "Content-Security-Policy" and not csp:
            assert name.lower() not in response.headers
        else:
            assert response.headers[name.lower()] == value, name


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
    """Bootstrap may be cached by the browser; it is not private."""
    response = await client.get("/static/bootstrap.min.css")
    assert response.status_code == 200
    assert response.headers.get("cache-control") != "no-store"
    assert_secure(response)


async def test_swagger_docs_are_exempt_from_the_csp() -> None:
    """The docs page needs a CDN; it exists only with ENABLE_DOCS and keeps the other headers."""
    app = create_app(
        settings=make_settings(enable_docs=True),
        blob_store=InMemoryBlobStore(),
        initial_admin=False,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        response = await c.get("/docs")
    assert response.status_code == 200
    assert_secure(response, csp=False)
