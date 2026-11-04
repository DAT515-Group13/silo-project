"""Schemas of the team endpoints."""

from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, StringConstraints

from app.schemas.common import InputModel, Username, reject_nul

# 1-100 characters after trimming. The constraints must come first, directly on `str`.
TeamName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=100),
    AfterValidator(reject_nul),
]


class TeamIn(InputModel):
    """Body of ``POST /teams``."""

    name: TeamName


class TeamOut(BaseModel):
    """A team."""

    id: int
    name: str
    owner_id: int
    created_at: datetime


class MemberOut(BaseModel):
    """A team member."""

    user_id: int
    username: str
    added_at: datetime


class TeamDetailOut(TeamOut):
    """A team with its members."""

    members: list[MemberOut]


class AddMemberIn(InputModel):
    """Body of ``POST /teams/{id}/members``."""

    username: Username
