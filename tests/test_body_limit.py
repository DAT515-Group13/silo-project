"""Request body size limit: small bodies everywhere except the two upload routes."""

from collections.abc import AsyncIterator

import httpx
import pytest
from starlette.types import Receive, Scope, Send

from app.middleware import MAX_BODY_BYTES, BodyLimitMiddleware
from app.models import Role
from tests.conftest import ActAs

pytestmark = pytest.mark.anyio

BIG = b"x" * (MAX_BODY_BYTES + 1)


async def test_declared_oversized_body_is_413(client: httpx.AsyncClient) -> None:
    """A Content-Length over the limit is refused before the body is read.

    The API answers in its JSON error shape, pages in plain text.
    """
    page = await client.post("/login", content=BIG)
    assert page.status_code == 413
    api = await client.post("/api/v1/auth/login", content=BIG)
    assert api.status_code == 413
    assert api.json() == {"detail": "Request body too large.", "code": "payload_too_large"}


@pytest.mark.parametrize(
    ("path", "content_type"),
    [
        ("/login", "application/x-www-form-urlencoded"),
        ("/api/v1/auth/login", "application/json"),
    ],
)
async def test_chunked_oversized_body_is_413(
    client: httpx.AsyncClient, path: str, content_type: str
) -> None:
    """Without Content-Length the bytes are counted while they arrive (the API answers in JSON)."""

    async def body() -> AsyncIterator[bytes]:
        for _ in range(3):
            yield BIG[: MAX_BODY_BYTES // 2 + 1]

    response = await client.post(path, content=body(), headers={"Content-Type": content_type})
    assert response.status_code == 413
    if path.startswith("/api/"):
        assert response.json()["code"] == "payload_too_large"


async def test_large_multipart_never_reaches_the_disk(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A big file part on a normal form is refused before Starlette can spool it (spec s. 2)."""

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("a temporary file was created")

    monkeypatch.setattr("starlette.formparsers.SpooledTemporaryFile", forbidden)
    response = await client.post("/login", files={"file": ("a.bin", BIG)})
    assert response.status_code == 413


async def test_upload_routes_are_not_limited(client: httpx.AsyncClient, act_as: ActAs) -> None:
    """Uploads stream to blob storage, so the two upload routes accept bodies over the limit."""
    act_as(Role.user)
    api = await client.post("/api/v1/files", files={"other": ("a.bin", BIG)})
    page = await client.post("/files/upload", files={"file": ("a.bin", BIG)})
    assert api.status_code == 422  # reached the route (no `file` part), not 413
    assert page.status_code == 403  # reached the route (no Origin), not 413


@pytest.mark.parametrize("path", ["/files/upload", "/api/v1/files"])
async def test_upload_routes_receive_the_whole_large_body(path: str) -> None:
    """Guards the exemption itself: 500 KB (far over the limit) reaches the upload routes intact.

    A stand-in app counts the bytes, so the real upload service (and its database) is not needed.
    """

    async def counting_app(scope: Scope, receive: Receive, send: Send) -> None:
        total = 0
        more = True
        while more:
            message = await receive()
            total += len(message.get("body", b""))
            more = message.get("more_body", False)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": str(total).encode()})

    async def body() -> AsyncIterator[bytes]:
        for _ in range(50):
            yield b"x" * 10_000

    transport = httpx.ASGITransport(app=BodyLimitMiddleware(counting_app))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        response = await c.post(path, content=body())
    assert (response.status_code, response.text) == (200, "500000")


async def test_refused_upload_still_reads_the_rest_of_the_body(
    client: httpx.AsyncClient, act_as: ActAs
) -> None:
    """A too-large upload is answered 413 only after the client finished sending.

    Otherwise the proxy can turn the 413 into a 502 (the app closes while the browser sends).
    """
    act_as(Role.user)
    sent: list[int] = []
    head = b'--b\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'

    async def body() -> AsyncIterator[bytes]:
        yield head
        for i in range(20):
            sent.append(i)
            yield b"x" * 1000
        yield b"\r\n--b--\r\n"

    response = await client.post(
        "/api/v1/files",
        content=body(),
        headers={
            "content-type": "multipart/form-data; boundary=b",
            "content-length": str(10**9),  # declared far over MAX_FILE_SIZE_BYTES
        },
    )
    assert (response.status_code, response.json()["code"]) == (413, "file_too_large")
    assert len(sent) == 20
