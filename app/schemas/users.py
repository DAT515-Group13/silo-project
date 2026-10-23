"""Schemas of the admin endpoints: user management and the audit log."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, StringConstraints

from app.models import ActorType, Outcome, Role, UserStatus
from app.schemas.common import InputModel


class AdminUserOut(BaseModel):
    """A user as shown to admins. Never contains the password hash."""

    id: int
    username: str
    role: Role
    status: UserStatus
    used_bytes: int
    created_at: datetime
    last_login_at: datetime | None = None
    # Number of files the user owns; the admin UI warns with it before a delete.
    # Only set in the user list.
    file_count: int | None = None


class AdminUserPatchIn(InputModel):
    """Body of ``PATCH /admin/users/{id}``. Status can only toggle active and disabled."""

    role: Role | None = None
    status: Literal[UserStatus.active, UserStatus.disabled] | None = None


class RejectIn(InputModel):
    """Optional body of ``POST /admin/users/{id}/reject``."""

    # Stored in the audit details; the cap keeps a single entry small.
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] | None = None


class AuditEntryOut(BaseModel):
    """One audit log row."""

    id: int
    created_at: datetime
    actor_type: ActorType
    actor_id: int | None = None
    actor_username: str | None = None
    action: str
    outcome: Outcome
    target_type: str | None = None
    target_id: str | None = None
    target_label: str | None = None
    ip: str | None = None
    request_id: str | None = None
    details: dict | None = None
