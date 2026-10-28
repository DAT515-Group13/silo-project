"""Uploads over HTTP that the app refuses early: the 3-at-a-time limit and the body drain.

No database: ``act_as`` replaces the login and a stand-in replaces the upload service.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack

import httpx
import pytest

from app.errors import FileTooLarge, StorageFull
from app.models import Role
from app.ratelimit import _FALLBACK_RETRY_AFTER as FALLBACK_RETRY_AFTER
from app.ratelimit import MAX_CONCURRENT_UPLOADS, upload_slot
from app.services import files
from tests.conftest import ActAs

pytestmark = pytest.mark.anyio

BOUNDARY = "testboundary"
CHUNK_COUNT = 20


async def test_fourth_parallel_upload_is_429(
    client: httpx.AsyncClient, act_as: ActAs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three uploads of one user run at once; the fourth is 429 rate_limited until one ends."""
    act_as(Role.user)
    release = asyncio.Event()
    all_running = asyncio.Event()
    running = 0

    async def held_upload(*args: object, **kwargs: object) -> None:
        nonlocal running
        running += 1
        if running == MAX_CONCURRENT_UPLOADS:
            all_running.set()
        await release.wait()
        raise FileTooLarge  # any ending will do; the test is about the slots

    monkeypatch.setattr(files, "upload", held_upload)

    async def upload() -> httpx.Response:
        return await client.post("/api/v1/files", files={"file": ("a.bin", b"data")})

    tasks = [asyncio.create_task(upload()) for _ in range(MAX_CONCURRENT_UPLOADS)]
    try:
        async with asyncio.timeout(5):
            await all_running.wait()

        fourth = await upload()
        assert (fourth.status_code, fourth.json()["code"]) == (429, "rate_limited")
        assert fourth.headers["retry-after"] == str(FALLBACK_RETRY_AFTER)
    finally:
        # Also after a failure: held uploads would keep their slots for the next test.
        release.set()
    results = await asyncio.gather(*tasks)
    assert [r.status_code for r in results] == [413] * MAX_CONCURRENT_UPLOADS
    assert running == MAX_CONCURRENT_UPLOADS  # the fourth never reached the service


@pytest.mark.parametrize(
    ("case", "status", "code"),
    [
        ("busy", 429, "rate_limited"),
        ("wrong part", 422, "validation_error"),
        ("service full", 507, "storage_full"),
    ],
)
async def test_refused_upload_still_reads_the_whole_body(
    client: httpx.AsyncClient,
    act_as: ActAs,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    status: int,
    code: str,
) -> None:
    """A refused upload is answered after the rest of the body was read (no proxy 502, D27).

    "service full" stands for the global cap: ``StorageFull`` is a ``QuotaExceeded``, so the
    route drains the body and answers 507 without any route change.
    """
    user = act_as(Role.user)
    field = "other" if case == "wrong part" else "file"  # a part that is not `file` is a 422
    sent = 0

    async def full(*args: object, **kwargs: object) -> None:
        raise StorageFull  # refused before reading the file, like step 2 of the upload

    if case == "service full":
        monkeypatch.setattr(files, "upload", full)

    async def body() -> AsyncIterator[bytes]:
        nonlocal sent
        head = f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{field}"; '
        yield (head + 'filename="a.bin"\r\n\r\n').encode()
        sent += 1
        for _ in range(CHUNK_COUNT):
            yield b"x" * 1000
            sent += 1
        yield f"\r\n--{BOUNDARY}--\r\n".encode()
        sent += 1

    async with AsyncExitStack() as stack:
        if case == "busy":  # all slots of this user are taken by other uploads
            for _ in range(MAX_CONCURRENT_UPLOADS):
                await stack.enter_async_context(upload_slot(user.id))
        response = await client.post(
            "/api/v1/files",
            content=body(),
            headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
        )

    assert (response.status_code, response.json()["code"]) == (status, code)
    assert sent == CHUNK_COUNT + 2  # the client could send everything
