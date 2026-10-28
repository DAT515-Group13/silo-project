"""Request and response shapes of the public link endpoints.

The full link URL is shown only once, in ``LinkCreatedOut``; listings (``LinkOut``) contain
neither the token nor the URL, because only a hash of the token is stored.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import InputModel


class LinkCreateIn(InputModel):
    """Body of ``POST /files/{id}/links``.

    The upper bound is ``PUBLIC_LINK_MAX_HOURS`` from the settings, checked by the service.
    """

    expires_in_hours: int = Field(default=24, ge=1)


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


class LinkExpiryIn(InputModel):
    """Body of ``PATCH /links/{id}``: the new lifetime, counted from now.

    The upper bound is ``PUBLIC_LINK_MAX_HOURS``, checked by the service.
    """

    expires_in_hours: int = Field(ge=1)


class MyLinkOut(LinkOut):
    """A link in the overview of all own links: ``LinkOut`` plus the file it belongs to."""

    file_id: uuid.UUID
    filename: str
