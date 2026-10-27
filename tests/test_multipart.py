"""Tests for the streaming multipart reader used by uploads.

They check that parts are read correctly however the body is cut into network chunks, and that
every kind of malformed upload becomes a validation error instead of a crash or a disk write.
No database is needed.
"""

from collections.abc import AsyncIterator

import anyio
import pytest
from starlette.requests import ClientDisconnect

from app.errors import ValidationFailed
from app.routers.multipart import MultipartReader, PartInfo, discard_body

pytestmark = pytest.mark.anyio

BOUNDARY = "testboundary"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"


def build_body(*parts: tuple[str, str | None, bytes]) -> bytes:
    """Build a multipart body from (name, filename or None, data) tuples."""
    out = b""
    for name, filename, data in parts:
        disposition = f'form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        out += f"--{BOUNDARY}\r\nContent-Disposition: {disposition}\r\n".encode()
        if filename is not None:
            out += b"Content-Type: text/plain\r\n"
        out += b"\r\n" + data + b"\r\n"
    return out + f"--{BOUNDARY}--\r\n".encode()


async def stream(body: bytes, size: int) -> AsyncIterator[bytes]:
    """Deliver the body in chunks of ``size`` bytes, like a slow network."""
    for i in range(0, len(body), size):
        yield body[i : i + size]


async def read_all(reader: MultipartReader) -> list[tuple[PartInfo, bytes]]:
    """Read every part completely."""
    result = []
    while (part := await reader.next_part()) is not None:
        result.append((part, b"".join([c async for c in reader.iter_data()])))
    return result


BODY = build_body(("csrf_token", None, b"abc123"), ("file", "../a.txt", b"hello\r\nworld" * 50))


@pytest.mark.parametrize("size", [1, 2, 7, 50, 10_000])
async def test_parts_are_the_same_for_any_chunk_size(size: int) -> None:
    """The body can be cut anywhere (even inside a boundary) and gives the same parts."""
    reader = MultipartReader(CONTENT_TYPE, stream(BODY, size), max_parts=2)
    (field, field_data), (upload, upload_data) = await read_all(reader)
    assert (field.name, field.filename, field_data) == ("csrf_token", None, b"abc123")
    assert (upload.name, upload.filename) == ("file", "../a.txt")
    assert upload.content_type == "text/plain"
    assert upload_data == b"hello\r\nworld" * 50


async def test_unread_part_is_skipped() -> None:
    """next_part() skips the rest of a part that was not read."""
    reader = MultipartReader(CONTENT_TYPE, stream(BODY, 5), max_parts=2)
    assert (await reader.next_part()).name == "csrf_token"  # type: ignore[union-attr]
    assert (await reader.next_part()).name == "file"  # type: ignore[union-attr]
    assert await reader.next_part() is None


async def test_empty_file_part() -> None:
    """A zero-byte file is a valid part with no data."""
    body = build_body(("file", "empty.txt", b""))
    reader = MultipartReader(CONTENT_TYPE, stream(body, 3), max_parts=1)
    [(part, data)] = await read_all(reader)
    assert part.filename == "empty.txt"
    assert data == b""


@pytest.mark.parametrize(
    "content_type",
    ["", "application/json", "multipart/form-data", "multipart/mixed; boundary=x"],
)
async def test_wrong_content_type_is_refused(content_type: str) -> None:
    """Only multipart/form-data with a boundary is accepted."""
    with pytest.raises(ValidationFailed):
        MultipartReader(content_type, stream(b"", 1), max_parts=1)


async def test_too_many_parts_are_refused() -> None:
    """More parts than max_parts is an error, so a body cannot hide extra fields."""
    body = build_body(("a", None, b"1"), ("b", None, b"2"), ("c", None, b"3"))
    reader = MultipartReader(CONTENT_TYPE, stream(body, 10), max_parts=2)
    with pytest.raises(ValidationFailed) as error:
        await read_all(reader)
    assert "too many" in error.value.errors[0]["message"]


async def test_oversized_part_headers_are_refused() -> None:
    """A part header over the limit is refused instead of buffered."""
    body = (
        f"--{BOUNDARY}\r\nX-Big: {'a' * 9000}\r\n"
        f'Content-Disposition: form-data; name="x"\r\n\r\ndata\r\n--{BOUNDARY}--\r\n'
    ).encode()
    reader = MultipartReader(CONTENT_TYPE, stream(body, 100), max_parts=1)
    with pytest.raises(ValidationFailed):
        await read_all(reader)


async def test_truncated_body_is_refused() -> None:
    """A body that stops before the closing boundary (client disconnect) is an error."""
    reader = MultipartReader(CONTENT_TYPE, stream(BODY[:-40], 20), max_parts=2)
    with pytest.raises(ValidationFailed) as error:
        await read_all(reader)
    assert "unexpectedly" in error.value.errors[0]["message"]


async def test_part_without_name_is_refused() -> None:
    """Every part needs a name in its Content-Disposition header."""
    body = f"--{BOUNDARY}\r\nContent-Disposition: form-data\r\n\r\nx\r\n--{BOUNDARY}--\r\n".encode()
    reader = MultipartReader(CONTENT_TYPE, stream(body, 8), max_parts=1)
    with pytest.raises(ValidationFailed) as error:
        await read_all(reader)
    assert "no name" in error.value.errors[0]["message"]


async def test_client_disconnect_is_a_validation_error() -> None:
    """A browser closing the connection mid-upload is a 422, not an unhandled error."""

    async def dropped() -> AsyncIterator[bytes]:
        yield BODY[:30]
        raise ClientDisconnect

    reader = MultipartReader(CONTENT_TYPE, dropped(), max_parts=2)
    with pytest.raises(ValidationFailed) as error:
        await read_all(reader)
    assert "unexpectedly" in error.value.errors[0]["message"]


# --- Draining the rest of a refused upload --------------------------------------------------------


@pytest.mark.parametrize(
    ("max_bytes", "chunks_read"),
    [(10_000_000, 1000), (450, 5)],  # whole rest; gives up at the first total above the limit
)
async def test_discard_body_reads_the_rest_up_to_the_limit(
    max_bytes: int, chunks_read: int
) -> None:
    """A refused upload reads what is left (the client can finish sending), but not forever."""
    seen: list[int] = []

    async def body() -> AsyncIterator[bytes]:
        for i in range(1000):
            seen.append(i)
            yield b"x" * 100

    await discard_body(body(), max_bytes=max_bytes)
    assert len(seen) == chunks_read


async def test_discard_body_ignores_a_client_disconnect() -> None:
    """A client that goes away while the body is drained is not an error."""

    async def body() -> AsyncIterator[bytes]:
        yield b"x"
        raise ClientDisconnect

    await discard_body(body(), max_bytes=10_000)


async def test_discard_body_gives_up_when_the_client_is_too_slow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client that stops sending cannot hold the request open for long."""
    monkeypatch.setattr("app.routers.multipart.DISCARD_TIMEOUT_SECONDS", 0.05)

    async def body() -> AsyncIterator[bytes]:
        yield b"x"
        await anyio.sleep(5)
        yield b"y"

    await discard_body(body(), max_bytes=10_000)
