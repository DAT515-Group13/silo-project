"""Building blocks shared by all schema modules: input base class, usernames, pages, errors.

Implements the username rule and the response shapes (errors, pagination).
"""

import re
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.security import PASSWORD_MAX_LENGTH

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


class InputModel(BaseModel):
    """Base class of every input schema: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")


def normalize_username(value: str) -> str:
    """Lowercase and validate a username.

    The value is stripped and lowercased first, so ``"Anna"`` is stored as ``"anna"``.

    Raises:
        ValueError: if the result is not 3-32 characters matching ``USERNAME_PATTERN``.
            Pydantic turns this into a 422 ``validation_error``.
    """
    normalized = value.strip().lower()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Username must be 3-32 characters: lowercase letters, digits, '.', '_' or '-', "
            "starting with a letter or digit."
        )
    return normalized


def _normalize_login_username(value: str) -> str:
    """Strip and lowercase a username for lookup without applying the registration pattern."""
    return value.strip().lower()


# Full username rule: used wherever a username is created or looked up by a user-facing form
# other than login (register, add team member, initial admin).
Username = Annotated[str, AfterValidator(normalize_username)]

# Login only normalizes and caps the length. A string that cannot be a valid username must
# behave like any unknown username (401 plus dummy hash), not produce a different error class
# (open question Q20).
LoginUsername = Annotated[
    str, AfterValidator(_normalize_login_username), Field(min_length=1, max_length=32)
]

# Only the hard upper limit lives here. The configurable minimum (PASSWORD_MIN_LENGTH) is checked
# by security.check_password_policy.
Password = Annotated[str, Field(max_length=PASSWORD_MAX_LENGTH)]


class UserRefOut(BaseModel):
    """Minimal public reference to a user (for example the owner of a file)."""

    id: int
    username: str


class Page[T](BaseModel):
    """Paginated list response: ``{items, total, page, size}``."""

    items: list[T]
    total: int
    page: int
    size: int


class ErrorFieldOut(BaseModel):
    """One field-level problem inside a validation error."""

    field: str
    message: str


class ErrorOut(BaseModel):
    """Error body of every endpoint; only used to document OpenAPI responses."""

    detail: str
    code: str
    errors: list[ErrorFieldOut] | None = None
