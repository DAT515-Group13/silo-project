"""Tests for the pure file rules: cleaning of file names and choosing content types.

These need no database. They check that dangerous names (paths, control characters) are cleaned,
that a file's type is detected from its first bytes instead of trusting the client, and that
types a browser would render are always downloaded as ``application/octet-stream``.
"""

import pytest
from pydantic import ValidationError

from app.errors import FileTooLarge, QuotaExceeded
from app.schemas.files import FileRenameIn, sanitize_filename
from app.services.files import (
    _limited,
    _with_head,
    choose_content_type,
    download_content_type,
    normalize_content_type,
    sniff_content_type,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("report.pdf", "report.pdf"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\a\\b.txt", "b.txt"),
        ("a\x00b\r\n.txt", "ab.txt"),
        ("  spaced.txt  ", "spaced.txt"),
        ("zażółć.txt", "zażółć.txt"),
        ("invoice\u202efdp.exe", "invoicefdp.exe"),  # right-to-left override is invisible
        ("a\x85b\u200b.txt", "ab.txt"),  # C1 control and zero-width space
    ],
)
def test_filename_is_cleaned(raw: str, expected: str) -> None:
    """Path parts and control characters are removed from a file name."""
    assert sanitize_filename(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "..", ".", "a/", "\x00\x01"])
def test_unusable_filename_is_refused(raw: str) -> None:
    """A name with nothing left after cleaning is a validation error."""
    with pytest.raises(ValueError, match="empty"):
        sanitize_filename(raw)


def test_long_filename_keeps_its_extension() -> None:
    """A name over 255 characters is shortened, but the extension survives."""
    result = sanitize_filename("x" * 300 + ".pdf")
    assert len(result) == 255
    assert result.endswith(".pdf")


def test_rename_schema_cleans_the_name() -> None:
    """The rename body uses the same cleaning (extra="forbid" is tested in test_schemas.py)."""
    assert FileRenameIn(filename="../a.txt").filename == "a.txt"
    with pytest.raises(ValidationError):
        FileRenameIn(filename="..")


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"%PDF-1.7 ...", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n....", "image/png"),
        (b"\xff\xd8\xff\xe0", "image/jpeg"),
        (b"GIF89a..", "image/gif"),
        (b"GIF87a..", "image/gif"),
        (b"PK\x03\x04..", "application/zip"),
        (b"\x1f\x8b\x08", "application/gzip"),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
        (b"\x00\x00\x00\x18ftypmp42", "video/mp4"),
        (b"\x00\x00\x00\x18ftypheic", None),  # HEIC shares "ftyp" but is not MP4
        (b"plain text", None),
        (b"", None),
    ],
)
def test_sniffing_by_first_bytes(head: bytes, expected: str | None) -> None:
    """Known formats are recognized by their signature, unknown ones give None."""
    assert sniff_content_type(head) == expected


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        ("text/HTML; charset=utf-8", "text/html"),
        ("application/pdf", "application/pdf"),
        (None, None),
        ("", None),
        ("a/b/c", None),
        ("x\r\ny", None),
        ("text", None),
        ("a/" + "b" * 130, None),
    ],
)
def test_client_content_type_is_normalized(client: str | None, expected: str | None) -> None:
    """Only a clean type/subtype survives; parameters are dropped."""
    assert normalize_content_type(client) == expected


def test_choice_prefers_detection_over_the_client() -> None:
    """Order: detected type, then the client's clean value, then octet-stream."""
    assert choose_content_type(b"%PDF-1", "text/plain") == "application/pdf"
    assert choose_content_type(b"hello", "text/plain") == "text/plain"
    assert choose_content_type(b"hello", "bad value") == "application/octet-stream"
    assert choose_content_type(b"hello", None) == "application/octet-stream"


def test_zip_signature_yields_to_a_more_precise_client_type() -> None:
    """A .docx is a ZIP file: its clean client type is kept, a plain ZIP stays a ZIP."""
    docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert choose_content_type(b"PK\x03\x04rest", docx) == docx
    assert choose_content_type(b"PK\x03\x04rest", None) == "application/zip"
    assert choose_content_type(b"PK\x03\x04rest", "not valid") == "application/zip"
    assert choose_content_type(b"PK\x03\x04rest", "text/html") == "application/zip"


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ("text/html", "application/octet-stream"),
        ("image/svg+xml", "application/octet-stream"),
        ("application/xhtml+xml", "application/octet-stream"),
        ("application/rss+xml", "application/octet-stream"),
        ("text/xml", "application/octet-stream"),
        ("application/pdf", "application/pdf"),  # harmless types are kept
    ],
)
def test_download_type_never_lets_the_browser_render(stored: str, expected: str) -> None:
    """Types a browser would render are sent as octet-stream; others keep their value."""
    assert download_content_type(stored) == expected


# --- Upload stream helpers -----------------------------------------------------------------------


async def chunks_of(*parts: bytes):
    for part in parts:
        yield part


@pytest.mark.anyio
async def test_head_is_peeked_without_losing_bytes() -> None:
    """The first bytes are used for type detection, and the stream still starts with them."""
    head, stream = await _with_head(chunks_of(b"%PDF", b"-1.4 ", b"x" * 100, b"end"))
    assert head.startswith(b"%PDF-1.4")
    assert len(head) == 32
    assert b"".join([c async for c in stream]) == b"%PDF-1.4 " + b"x" * 100 + b"end"


@pytest.mark.anyio
async def test_head_of_a_short_or_empty_stream() -> None:
    """A stream shorter than the sniff window, or empty, is passed on completely."""
    head, stream = await _with_head(chunks_of(b"hi"))
    assert head == b"hi"
    assert b"".join([c async for c in stream]) == b"hi"
    head, stream = await _with_head(chunks_of())
    assert head == b""
    assert [c async for c in stream] == []


@pytest.mark.anyio
async def test_limited_stops_at_the_size_limit_and_the_quota() -> None:
    """Counting stops a stream the moment a limit is passed; the size limit wins a tie."""
    ok = [c async for c in _limited(chunks_of(b"abc", b"de"), max_size=5, remaining=5)]
    assert b"".join(ok) == b"abcde"
    with pytest.raises(FileTooLarge):
        [c async for c in _limited(chunks_of(b"abc", b"def"), max_size=5, remaining=100)]
    with pytest.raises(QuotaExceeded):
        [c async for c in _limited(chunks_of(b"abc", b"def"), max_size=100, remaining=5)]
    with pytest.raises(FileTooLarge):
        [c async for c in _limited(chunks_of(b"abcdef"), max_size=5, remaining=5)]
