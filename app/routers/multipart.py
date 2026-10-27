"""Streaming reader for ``multipart/form-data`` request bodies (used by file uploads).

Starlette's ``request.form()`` and ``UploadFile`` write every part larger than 1 MiB to a
temporary file on the local disk. Silo must not write to the local filesystem, and an upload
should flow straight on to blob storage. This reader instead hands out the data of one part at a
time as chunks, and keeps in memory only what the parser is currently working on.

Typical use (an upload form with a hidden CSRF field before the file)::

    reader = MultipartReader(content_type, request.stream(), max_parts=2)
    first = await reader.next_part()              # the csrf_token field, small
    token = b"".join([chunk async for chunk in reader.iter_data()])
    second = await reader.next_part()             # the file
    async for chunk in reader.iter_data(): ...    # streamed on to the blob store

Every problem with the body (wrong content type, no boundary, too many parts, oversized part
headers, truncated body) is raised as ``ValidationFailed``, which the app turns into a 422.
"""

import asyncio
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from python_multipart import MultipartParser
from python_multipart.exceptions import FormParserError
from python_multipart.multipart import parse_options_header
from starlette.requests import ClientDisconnect

from app.errors import ValidationFailed

DEFAULT_MAX_HEADER_BYTES = 8 * 1024
# After a refused upload the server still reads and drops up to MAX_FILE_SIZE_BYTES plus this
# much (and for at most DISCARD_TIMEOUT_SECONDS), so a file slightly over the limit is received
# completely and the client sees the real error. Files far over it get the connection closed.
DISCARD_EXTRA_BYTES = 5 * 1024 * 1024
DISCARD_TIMEOUT_SECONDS = 60.0


@dataclass(frozen=True)
class PartInfo:
    """What the headers of one part say."""

    name: str
    filename: str | None
    content_type: str | None


def _invalid(message: str) -> ValidationFailed:
    """The one error type of this module: a malformed upload body."""
    return ValidationFailed([{"field": "file", "message": message}])


class MultipartReader:
    """Reads the parts of a multipart body one after another, as a stream.

    Parts must be consumed in order: call ``next_part()``, then read its data with
    ``iter_data()``. Calling ``next_part()`` before a part is fully read skips the rest of it.
    """

    def __init__(
        self,
        content_type: str,
        body: AsyncIterator[bytes],
        *,
        max_parts: int,
        max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
    ) -> None:
        """Prepare the parser.

        Raises:
            ValidationFailed: if ``content_type`` is not ``multipart/form-data`` with a boundary.
        """
        media_type, options = parse_options_header(content_type)
        boundary = options.get(b"boundary")
        if media_type != b"multipart/form-data" or not boundary:
            raise _invalid("Expected a multipart/form-data upload.")

        self._body = body.__aiter__()
        self._max_parts = max_parts
        self._parts_seen = 0
        self._ended = False  # the closing boundary was seen
        self._eof = False  # the request body is used up
        # The parser callbacks only record events; the async methods below consume them.
        self._events: deque[tuple[str, Any]] = deque()
        self._header_name = bytearray()
        self._header_value = bytearray()
        self._headers: dict[bytes, bytes] = {}

        try:
            self._parser = MultipartParser(
                boundary,
                {
                    "on_part_data": self._on_data,
                    "on_part_end": lambda: self._events.append(("part_end", b"")),
                    "on_header_field": self._on_header_field,
                    "on_header_value": self._on_header_value,
                    "on_header_end": self._on_header_end,
                    "on_headers_finished": self._on_headers_finished,
                    "on_end": self._on_end,
                },
                max_header_size=max_header_bytes,
            )
        except FormParserError:
            raise _invalid("Invalid multipart boundary.") from None

    # --- Parser callbacks (synchronous, they only record what happened) ---------------------------

    def _on_data(self, data: bytes, start: int, end: int) -> None:
        # Copy: the parser reuses the buffer it passes in.
        self._events.append(("data", bytes(data[start:end])))

    def _on_header_field(self, data: bytes, start: int, end: int) -> None:
        self._header_name += data[start:end]

    def _on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._header_value += data[start:end]

    def _on_header_end(self) -> None:
        self._headers[bytes(self._header_name).lower()] = bytes(self._header_value)
        self._header_name.clear()
        self._header_value.clear()

    def _on_headers_finished(self) -> None:
        # The headers travel inside the event: with a large chunk the parser can finish several
        # parts before the async code below reads the first one.
        self._events.append(("headers", self._headers))
        self._headers = {}

    def _on_end(self) -> None:
        self._ended = True

    # --- Feeding the parser ---------------------------------------------------------------------

    async def _pump(self) -> None:
        """Read one chunk of the request body and give it to the parser.

        Raises:
            ValidationFailed: if the body is malformed or ends before the closing boundary.
        """
        if self._eof:
            raise _invalid("The upload ended unexpectedly.")
        try:
            chunk = await self._body.__anext__()
        except ClientDisconnect:
            # The browser closed the connection mid-upload: a normal event, not a server error.
            self._eof = True
            raise _invalid("The upload ended unexpectedly.") from None
        except StopAsyncIteration:
            self._eof = True
            try:
                self._parser.finalize()
            except FormParserError:
                raise _invalid("The upload is malformed.") from None
            if not self._ended:
                # The client stopped sending (or disconnected) before the last boundary.
                raise _invalid("The upload ended unexpectedly.") from None
            return
        try:
            self._parser.write(chunk)
        except FormParserError:
            raise _invalid("The upload is malformed.") from None

    # --- Public API -----------------------------------------------------------------------------

    async def next_part(self) -> PartInfo | None:
        """Move to the next part and return its headers, or None after the last part.

        Raises:
            ValidationFailed: malformed body, too many parts, or a part without a name.
        """
        while True:
            while self._events:
                kind, payload = self._events.popleft()
                if kind == "headers":
                    return self._finish_headers(payload)
                # "data" and "part_end" of a part that was not read to the end are skipped.
            if self._ended:
                return None
            await self._pump()

    def _finish_headers(self, headers: dict[bytes, bytes]) -> PartInfo:
        """Turn the collected headers of the new part into a ``PartInfo``."""
        self._parts_seen += 1
        if self._parts_seen > self._max_parts:
            raise _invalid("The upload contains too many parts.")

        _, options = parse_options_header(headers.get(b"content-disposition", b""))
        name = options.get(b"name")
        if not name:
            raise _invalid("A part of the upload has no name.")
        filename = options.get(b"filename")
        content_type = headers.get(b"content-type")
        return PartInfo(
            name=name.decode("utf-8", errors="replace"),
            filename=filename.decode("utf-8", errors="replace") if filename is not None else None,
            content_type=content_type.decode("latin-1").strip() if content_type else None,
        )

    async def iter_data(self) -> AsyncIterator[bytes]:
        """Yield the data of the current part in chunks until the part ends.

        Raises:
            ValidationFailed: if the body is malformed or cut off inside the part.
        """
        while True:
            while self._events:
                kind, data = self._events.popleft()
                if kind == "data":
                    yield data
                elif kind == "part_end":
                    return
            await self._pump()


async def drain_refused_upload(
    body: AsyncIterator[bytes], *, declared_size: int | None, max_file_bytes: int
) -> None:
    """Drain the body of a refused upload, unless it is announced as too big to drain.

    ``declared_size`` is the Content-Length. Over the cap, draining cannot finish anyway (the
    connection is closed after the cap), so it would only hold the request open for nothing.
    """
    cap = max_file_bytes + DISCARD_EXTRA_BYTES
    if (declared_size or 0) <= cap:
        await discard_body(body, max_bytes=cap)


async def discard_body(body: AsyncIterator[bytes], *, max_bytes: int) -> None:
    """Read and drop what is left of a request body, so the refusal reaches the client.

    A refused upload (too large, quota full) is answered before the file is read. If the app
    answers and closes while the browser is still sending, the proxy may report the broken
    connection as ``502`` instead of the real ``413``. Reading the rest first lets the client
    finish sending. It gives up after ``max_bytes`` or ``DISCARD_TIMEOUT_SECONDS``, so a huge or
    slow body cannot hold the request open; the connection is then closed as before.
    Never raises: a disconnect or a timeout just ends the draining.
    """
    total = 0
    try:
        async with asyncio.timeout(DISCARD_TIMEOUT_SECONDS):
            async for chunk in body:
                total += len(chunk)
                if total > max_bytes:
                    return
    except (TimeoutError, ClientDisconnect):
        return
