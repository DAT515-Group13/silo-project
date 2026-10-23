"""Schemas of the public link endpoints. Owned by B."""

from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import InputModel


class LinkCreateIn(InputModel):
    """Body of ``POST /files/{id}/links``."""

    expires_in_hours: int = 24


class LinkCreatedOut(BaseModel):
    """Response of link creation. The URL is returned only here (example 9.4)."""

    id: int
    url: str
    expires_at: datetime


class LinkOut(BaseModel):
    """A link in a listing. Contains neither the token nor the URL."""

    id: int
    expires_at: datetime
    revoked_at: datetime | None = None
    download_count: int
    created_at: datetime
