"""Public link rules. More tests are added together with the links service (step 4.6)."""

import pytest
from pydantic import ValidationError

from app.schemas.links import LinkCreateIn


def test_link_hours_must_be_positive() -> None:
    """Link lifetime defaults to 24 hours and must be at least 1."""
    assert LinkCreateIn().expires_in_hours == 24
    with pytest.raises(ValidationError):
        LinkCreateIn(expires_in_hours=0)
