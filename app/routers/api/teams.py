"""Team endpoints.

Routers only parse the request, call one service function and build the response. Every
access rule lives in ``services/teams.py`` and ``permissions.py``.
"""

from fastapi import APIRouter, Request

from app.models import Team
from app.ratelimit import limit
from app.routers.common import ApiUser, AuditCtx, DbSession, PageNumber, PageSize, file_out
from app.schemas.common import Page
from app.schemas.files import FileOut
from app.schemas.teams import AddMemberIn, MemberOut, TeamDetailOut, TeamIn, TeamOut
from app.services import teams

router = APIRouter(prefix="/api/v1", tags=["teams"])


def team_out(team: Team) -> TeamOut:
    """Build the response for one team."""
    return TeamOut(id=team.id, name=team.name, owner_id=team.owner_id, created_at=team.created_at)


@router.get("/teams", response_model=list[TeamOut])
@limit("read")
async def list_teams(request: Request, user: ApiUser, session: DbSession) -> list[TeamOut]:
    """Teams the current user belongs to."""
    return [team_out(team) for team in await teams.list_my_teams(session, user)]


@router.post("/teams", status_code=201, response_model=TeamOut)
@limit("write")
async def create_team(
    request: Request, body: TeamIn, user: ApiUser, ctx: AuditCtx, session: DbSession
) -> TeamOut:
    """Create a team; the creator becomes owner and member.

    Errors: 403 `role_required` for a plain user, 409 `team_name_taken`.
    """
    return team_out(await teams.create_team(session, user, body.name, ctx))


@router.get("/teams/{team_id}", response_model=TeamDetailOut)
@limit("read")
async def get_team(
    request: Request, team_id: int, user: ApiUser, session: DbSession
) -> TeamDetailOut:
    """A team with its members. Members only, everybody else gets 404."""
    detail = await teams.get_team(session, user, team_id)
    members = [
        MemberOut(user_id=m.user_id, username=m.username, added_at=m.added_at)
        for m in detail.members
    ]
    return TeamDetailOut(**team_out(detail.team).model_dump(), members=members)


@router.delete("/teams/{team_id}", status_code=204)
@limit("write")
async def delete_team(
    request: Request, team_id: int, user: ApiUser, ctx: AuditCtx, session: DbSession
) -> None:
    """Delete a team (owner or admin). Files stay; their shares with the team go."""
    await teams.delete_team(session, user, team_id, ctx)


@router.get("/teams/{team_id}/files", response_model=Page[FileOut])
@limit("read")
async def list_team_files(
    request: Request,
    team_id: int,
    user: ApiUser,
    session: DbSession,
    page: PageNumber = 1,
    size: PageSize = 20,
) -> Page[FileOut]:
    """Files shared with the team, newest first. Members only."""
    items, total = await teams.list_team_files(session, user, team_id, page=page, size=size)
    return Page[FileOut](
        items=[file_out(item, user.id) for item in items], total=total, page=page, size=size
    )


@router.post("/teams/{team_id}/members", status_code=204)
@limit("write")
async def add_member(
    request: Request,
    team_id: int,
    body: AddMemberIn,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
) -> None:
    """Add an active account by username (team owner). Always 204, whether or not it existed."""
    await teams.add_member(session, user, team_id, body.username, ctx)


@router.delete("/teams/{team_id}/members/{user_id}", status_code=204)
@limit("write")
async def remove_member(
    request: Request,
    team_id: int,
    user_id: int,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
) -> None:
    """Remove a member (team owner) or leave the team (the member themself).

    Errors: 409 `owner_cannot_leave`; 404 for no access or a user who is not a member.
    """
    await teams.remove_member(session, user, team_id, user_id, ctx)
