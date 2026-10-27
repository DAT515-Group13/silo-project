"""Request and response shapes of the file endpoints.

``FileOut`` is what the API returns for a file (never the internal blob name). The rename body
and ``sanitize_filename`` make sure a stored file name is a plain name: no folders, no control
characters, at most 255 characters.
"""

import unicodedata
import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel

from app.schemas.common import InputModel, UserRefOut

MAX_FILENAME_LENGTH = 255
NO_FILE_MESSAGE = "Choose a file to upload."


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
    # make "invoice<U+202E>fdp.exe" look like "invoiceexe.pdf") are removed.
    name = "".join(ch for ch in name if unicodedata.category(ch) not in ("Cc", "Cf")).strip()
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

    filename: Filename


class FileTeamOut(BaseModel):
    """A team a file is shared with (``GET /files/{id}/teams``)."""

    id: int
    name: str
