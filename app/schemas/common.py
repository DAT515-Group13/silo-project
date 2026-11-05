"""Building blocks shared by all schema modules: input base class, usernames, passwords, pages."""

import re
from typing import Annotated

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field

from app.security import PASSWORD_MAX_LENGTH, normalize_password

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


def reject_nul(value: str) -> str:
    """Refuse a NUL character: PostgreSQL cannot store one in text or JSONB, which would be a 500.

    Raises:
        ValueError: if the value contains one. Pydantic turns this into a 422.
    """
    if "\x00" in value:
        raise ValueError("Text must not contain a NUL character.")
    return value


def has_broken_character(value: str) -> bool:
    """True if the text has half of a two-part character, which cannot be encoded as UTF-8.

    JSON can carry one (written like ``\\ud800``). Python accepts it as text, but Argon2 and
    PostgreSQL need UTF-8 bytes, so it would be a 500. No real character is in this range.
    """
    return any("\ud800" <= char <= "\udfff" for char in value)


def reject_broken_character(value: str) -> str:
    """Refuse half a two-part character, so it is a 422 and never a 500.

    Raises:
        ValueError: if the value contains one. Pydantic turns this into a 422.
    """
    if has_broken_character(value):
        raise ValueError("Text must not contain an invalid character.")
    return value


def _normalize_login_username(value: str) -> str:
    """Strip and lowercase a username for lookup without applying the registration pattern."""
    return value.strip().lower()


# Free text that reaches PostgreSQL: stored, or compared in a query.
NulFreeText = Annotated[str, AfterValidator(reject_nul)]

# Full username rule: used wherever a username is created or looked up by a user-facing form
# other than login (register, add team member, initial admin).
Username = Annotated[str, AfterValidator(normalize_username)]

# Login only normalizes and caps the length. A string that cannot be a valid username must
# behave like any unknown username (401 plus dummy hash), not produce a different error class.
LoginUsername = Annotated[
    str, AfterValidator(_normalize_login_username), Field(min_length=1, max_length=32)
]

# Only the hard upper limit lives here. The configurable minimum (PASSWORD_MIN_LENGTH) is checked
# by security.check_password_policy. The text is normalised (NFKC) first, so the limit counts the
# same characters as the policy check and the hash (some characters grow: one becomes up to 18).
Password = Annotated[
    str,
    BeforeValidator(lambda value: normalize_password(value) if isinstance(value, str) else value),
    Field(max_length=PASSWORD_MAX_LENGTH),
    AfterValidator(reject_broken_character),
]


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
