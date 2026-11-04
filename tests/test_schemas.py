"""Validation rules of the input schemas."""

import pytest
from pydantic import ValidationError

from app.schemas.auth import LoginIn, RefreshIn, RegisterIn
from app.schemas.common import normalize_username
from app.schemas.links import LinkCreateIn, LinkUpdateIn
from app.schemas.teams import AddMemberIn, TeamIn


def test_unknown_field_is_rejected() -> None:
    """Input schemas use extra="forbid"."""
    with pytest.raises(ValidationError):
        RegisterIn(username="anna", password="x" * 12, role="admin")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "username",
    [
        "ab",  # too short
        "a" * 33,  # too long
        ".anna",  # must start with a letter or digit
        "an na",  # space
        "anna@example.org",  # email-like input is not a username
        "anná",  # non-ASCII
        "",
    ],
)
def test_invalid_username_is_rejected(username: str) -> None:
    """Usernames must match ^[a-z0-9][a-z0-9._-]{2,31}$."""
    with pytest.raises(ValidationError):
        RegisterIn(username=username, password="x" * 12)
    with pytest.raises(ValueError):
        normalize_username(username)


@pytest.mark.parametrize("username", ["abc", "a" * 32, "9lives", "a.b_c-d", "Anna", "  Anna "])
def test_valid_username_is_accepted(username: str) -> None:
    """Boundary lengths and punctuation are accepted; names are stripped and lowercased."""
    expected = username.strip().lower()
    assert RegisterIn(username=username, password="x" * 12).username == expected
    assert AddMemberIn(username=username).username == expected


def test_login_username_is_only_normalized() -> None:
    """Login never fails on username format, so it cannot reveal which names are valid."""
    assert LoginIn(username=" Not A Valid Name! ", password="x").username == "not a valid name!"
    with pytest.raises(ValidationError):
        LoginIn(username="a" * 33, password="x")


def test_password_has_hard_upper_limit_only() -> None:
    """Schemas enforce the 128 character maximum; the minimum is configurable."""
    assert RegisterIn(username="anna", password="short").password == "short"
    with pytest.raises(ValidationError):
        RegisterIn(username="anna", password="x" * 129)
    assert RegisterIn(username="anna", password="x" * 128)


def test_refresh_token_has_a_size_limit() -> None:
    """A real token has 43 characters; a huge body is refused before it is hashed."""
    assert RefreshIn(refresh_token="x" * 64)
    with pytest.raises(ValidationError):
        RefreshIn(refresh_token="x" * 65)


def test_team_name_is_trimmed_and_length_limited() -> None:
    """Team names are 1-100 characters after trimming."""
    assert TeamIn(name="  Backend  ").name == "Backend"
    assert TeamIn(name="a" * 100)
    for bad in ("", "   ", "a" * 101):
        with pytest.raises(ValidationError):
            TeamIn(name=bad)


def test_link_hours_must_be_positive() -> None:
    """Creating defaults to 24 hours, changing has no default; both need at least 1 hour."""
    assert LinkCreateIn().expires_in_hours == 24
    with pytest.raises(ValidationError):
        LinkCreateIn(expires_in_hours=0)
    with pytest.raises(ValidationError):
        LinkUpdateIn()  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        LinkUpdateIn(expires_in_hours=0)
