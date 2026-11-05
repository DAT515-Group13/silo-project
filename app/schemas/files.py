"""Request and response shapes of the file endpoints.

``FileOut`` is what the API returns for a file (never the internal blob name). The rename body
and ``sanitize_filename`` make sure a stored file name is a plain name: no folders, no control
characters, at most 255 characters.
"""

import unicodedata
import uuid
from datetime import datetime
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import AfterValidator, BaseModel

from app.schemas.common import InputModel, UserRefOut

MAX_FILENAME_LENGTH = 255
NO_FILE_MESSAGE = "Choose a file to upload."


# Allowlist of extensions (OWASP File Upload Cheat Sheet: a blocklist is weak on its own). Programs,
# scripts, HTML, SVG and XML are left out on purpose; so are names without an extension.
ALLOWED_EXTENSIONS = frozenset(
    ".pdf .doc .docx .xls .xlsx .ppt .pptx .odt .ods .odp .rtf .txt .md .csv .tsv .json "
    ".png .jpg .jpeg .gif .webp .bmp .tif .tiff .heic "
    ".mp3 .wav .ogg .flac .m4a .mp4 .mov .webm .mkv .avi "
    ".zip .gz .tar .7z .rar "
    ".bin".split()  # .bin: scripts/smoke-test.sh uploads smoke.bin
)


def file_extension(filename: str) -> str:
    """Lower-case extension with its dot, ignoring trailing dots and spaces (Windows drops them)."""
    return PurePosixPath(filename.rstrip(". ")).suffix.lower()


def has_allowed_extension(filename: str) -> bool:
    """True if the extension of ``filename`` is on the allowlist."""
    return file_extension(filename) in ALLOWED_EXTENSIONS


def _require_allowed_extension(value: str) -> str:
    """Rename validator: the new name needs an allowed extension (a 422)."""
    if not has_allowed_extension(value):
        raise ValueError("This file type is not allowed.")
    return value


def sanitize_filename(value: str) -> str:
    """Clean a client-supplied file name before it is stored.

    Keeps only the part after the last ``/`` or ``\\`` (browsers used to send full Windows
    paths), removes control and invisible direction characters and surrounding spaces, and
    shortens names over 255 characters while keeping the extension.

    Raises:
        ValueError: if nothing usable is left. Pydantic turns this into a 422.
    """
    name = value.replace("\\", "/").rsplit("/", 1)[-1]
    # Categories Cc (control) and Cf (format, e.g. U+202E "right-to-left override", which can
    # make "invoice<U+202E>fdp.exe" look like "invoiceexe.pdf") are removed. So is Cs: half of a
    # two-part character, which PostgreSQL cannot store.
    name = "".join(ch for ch in name if unicodedata.category(ch) not in ("Cc", "Cf", "Cs")).strip()
    if name in ("", ".", ".."):
        raise ValueError("Filename must not be empty.")
    if len(name) > MAX_FILENAME_LENGTH:
        stem, dot, extension = name.rpartition(".")
        # Keep a short extension; a "name" that is only a long extension is simply cut.
        if dot and 0 < len(extension) < 20 and stem:
            name = stem[: MAX_FILENAME_LENGTH - len(extension) - 1] + "." + extension
        else:
            name = name[:MAX_FILENAME_LENGTH]
    return name


Filename = Annotated[str, AfterValidator(sanitize_filename)]


class FileOut(BaseModel):
    """File metadata. Never contains the blob name."""

    id: uuid.UUID
    filename: str
    content_type: str
    size_bytes: int
    owner: UserRefOut
    is_owner: bool
    created_at: datetime


class FileRenameIn(InputModel):
    """Body of ``PATCH /files/{id}``."""

    filename: Annotated[Filename, AfterValidator(_require_allowed_extension)]


class FileTeamOut(BaseModel):
    """A team a file is shared with (``GET /files/{id}/teams``)."""

    id: int
    name: str
