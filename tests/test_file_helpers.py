"""Tests for the pure file rules: cleaning of file names and choosing content types.

These need no database. They check that dangerous names (paths, control characters) are cleaned,
that a file's type is detected from its first bytes instead of trusting the client, and that
types a browser would render are always downloaded as ``application/octet-stream``.
"""

import pytest

from app.errors import (
    FileTooLarge,
    QuotaExceeded,
    StorageFull,
    StorageUnavailable,
    ValidationFailed,
)
from app.schemas.files import sanitize_filename
from app.services.files import (
    _count_failed_upload,
    _limited,
    _with_head,
    choose_content_type,
    download_content_type,
    normalize_content_type,
    sniff_content_type,
)
from tests.conftest import sample


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
    """Order: detected type, then the client's clean value, then octet-stream (ZIP is special)."""
    assert choose_content_type(b"%PDF-1", "text/plain") == "application/pdf"
    assert choose_content_type(b"hello", "text/plain") == "text/plain"
    assert choose_content_type(b"hello", "bad value") == "application/octet-stream"
    assert choose_content_type(b"hello", None) == "application/octet-stream"
    # A .docx is a ZIP file: its clean client type is kept, a plain ZIP stays a ZIP.
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
    """The first bytes are used for type detection, and no byte is lost from the stream."""
    head, stream = await _with_head(chunks_of(b"%PDF", b"-1.4 ", b"x" * 100, b"end"))
    assert head.startswith(b"%PDF-1.4")
    assert len(head) == 32
    assert b"".join([c async for c in stream]) == b"%PDF-1.4 " + b"x" * 100 + b"end"
    # A stream shorter than the sniff window, or empty, is passed on completely.
    head, stream = await _with_head(chunks_of(b"hi"))
    assert head == b"hi"
    assert b"".join([c async for c in stream]) == b"hi"
    head, stream = await _with_head(chunks_of())
    assert head == b""
    assert [c async for c in stream] == []


@pytest.mark.parametrize(
    ("limits", "error"),
    [
        # (max_size, remaining, global_remaining); None = no total cap.
        ((5, 5, None), None),  # exactly at every limit fits
        ((5, 5, 5), None),
        ((4, 100, None), FileTooLarge),
        ((100, 4, None), QuotaExceeded),
        ((100, 100, 4), StorageFull),
        ((4, 4, 4), FileTooLarge),  # the size limit wins a tie
        ((100, 4, 4), QuotaExceeded),  # then the user's own quota, then the service cap
    ],
    ids=[
        "fits",
        "fits-with-cap",
        "too-large",
        "own-quota",
        "service-full",
        "tie-size",
        "tie-quota",
    ],
)
@pytest.mark.anyio
async def test_limited_stops_at_the_first_limit_passed(
    limits: tuple[int, int, int | None], error: type[Exception] | None
) -> None:
    """Counting stops at the chunk that passes a limit: that chunk is never passed on.

    The stream is 3 + 2 bytes. The order of the checks decides the message: file too large,
    the user's own quota, then the service's total cap.
    """
    max_size, remaining, global_remaining = limits
    stream = _limited(
        chunks_of(b"abc", b"de"),
        max_size=max_size,
        remaining=remaining,
        global_remaining=global_remaining,
    )
    yielded: list[bytes] = []
    if error is None:
        yielded = [c async for c in stream]
        assert yielded == [b"abc", b"de"]
        return
    with pytest.raises(error) as raised:
        async for chunk in stream:
            yielded.append(chunk)
    assert type(raised.value) is error  # exact class: a QuotaExceeded is never a StorageFull
    assert yielded == [b"abc"]  # the chunk that passed the limit was not sent to storage


@pytest.mark.parametrize(
    ("exc", "label"),
    [
        (FileTooLarge(), "too_large"),
        (QuotaExceeded(), "quota_exceeded"),
        (StorageFull(), "storage_full"),  # a subclass of QuotaExceeded, so checked first
        (StorageUnavailable(), "storage_error"),
        (ValidationFailed([]), None),  # the client's mistake, not a refused upload
    ],
)
def test_failed_upload_is_counted_under_one_label(exc: Exception, label: str | None) -> None:
    """A refused upload adds 1 to exactly one ``silo_uploads_total`` label (section 8.3)."""
    labels = ["too_large", "quota_exceeded", "storage_full", "storage_error"]
    before = {name: sample("silo_uploads_total", result=name) for name in labels}
    _count_failed_upload(exc)
    change = {name: sample("silo_uploads_total", result=name) - before[name] for name in labels}
    assert change == {name: (1 if name == label else 0) for name in labels}
