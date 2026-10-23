"""Schemas of the file endpoints. Owned by B."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import InputModel, UserRefOut


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

    filename: str
