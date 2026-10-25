"""Schemas of the auth and account endpoints."""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from app.models import Role
from app.schemas.common import InputModel, LoginUsername, Password, Username


class RegisterIn(InputModel):
    """Body of ``POST /auth/register``."""

    username: Username
    password: Password


class LoginIn(InputModel):
    """Body of ``POST /auth/login``."""

    username: LoginUsername
    password: Password


# The one body of the 202 answer in `approval` mode: identical whether or not the username
# existed (no enumeration).
REGISTRATION_ACCEPTED_MESSAGE = "Registration received. An admin must approve the account."


class RegistrationAcceptedOut(BaseModel):
    """Body of ``202`` from ``POST /auth/register`` in ``approval`` mode."""

    detail: str = REGISTRATION_ACCEPTED_MESSAGE


class RefreshIn(InputModel):
    """Body of ``POST /auth/refresh``."""

    # Real tokens have 43 characters; the cap keeps a huge body from being hashed.
    refresh_token: Annotated[str, Field(max_length=64)]


class UserBriefOut(BaseModel):
    """The user part of a token response."""

    id: int
    username: str
    role: Role


class TokenPairOut(BaseModel):
    """Response of login and refresh (example 9.1)."""

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - token type, not a secret
    expires_in: int
    refresh_expires_in: int
    user: UserBriefOut


class MeOut(BaseModel):
    """Response of ``GET /me`` (example 9.2)."""

    id: int
    username: str
    role: Role
    used_bytes: int
    quota_bytes: int


class SessionOut(BaseModel):
    """One active session of the current user (example 9.6)."""

    id: uuid.UUID
    created_at: datetime
    last_used_at: datetime
    ip: str | None = None
    user_agent: str | None = None
    current: bool
