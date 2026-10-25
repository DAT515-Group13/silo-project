"""Team pages and their form actions.

Each form action calls the same service function as its JSON counterpart in
``routers/api/teams.py``, with the same permissions, rate limits and audit entries. Every POST
is protected by ``CsrfChecked``. Domain errors that are not handled here (404, 409
``owner_cannot_leave``) become the HTML error page through the exception handler.
"""

from typing import Annotated

from fastapi import APIRouter, Form, Request, Response
from pydantic import ValidationError

from app.config import Settings
from app.errors import RoleRequired, TeamNameTaken
from app.permissions import CurrentUser, can_create_team, can_delete_team, can_manage_members
from app.ratelimit import limit
from app.routers.common import (
    CsrfChecked,
    DbSession,
    IntId,
    PageAuditCtx,
    PageNumber,
    PageUser,
    SettingsDep,
    file_out,
    render_page,
    see_other,
    validation_messages,
)
from app.schemas.teams import AddMemberIn, TeamIn
from app.services import teams

router = APIRouter(include_in_schema=False)

FILES_PER_PAGE = 20

# Shown after every add-member request: it must not reveal whether the account exists (8.1).
MEMBER_ADD_NOTICE = "If an active account with this username exists, it is now a member."


# --- Team list and creation ----------------------------------------------------------------------


async def _teams_page(
    request: Request,
    session: DbSession,
    settings: Settings,
    user: CurrentUser,
    *,
    name: str = "",
    errors: list[str] | None = None,
    status_code: int = 200,
) -> Response:
    """Render ``teams.html`` with the user's teams and the create form (if allowed)."""
    my_teams = await teams.list_my_teams(session, user)
    return render_page(
        request,
        settings,
        user,
        "teams.html",
        {
            "teams": my_teams,
            "can_create": can_create_team(user),
            "name": name,
            "errors": errors or [],
        },
        status_code=status_code,
    )


@router.get("/teams")
@limit("read")
async def teams_page(
    request: Request, user: PageUser, session: DbSession, settings: SettingsDep
) -> Response:
    """List the teams the user belongs to; team leads and admins also get a create form."""
    return await _teams_page(request, session, settings, user)


@router.post("/teams", dependencies=[CsrfChecked])
@limit("write")
async def create_team_submit(
    request: Request,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    settings: SettingsDep,
    name: Annotated[str, Form()] = "",
) -> Response:
    """Create a team and open its page; problems show the list again with a message."""
    # Checked first, so a plain user gets the 403 without any database work (D19).
    if not can_create_team(user):
        raise RoleRequired
    try:
        form = TeamIn.model_validate({"name": name})
        team = await teams.create_team(session, user, form.name, ctx)
    except ValidationError as exc:
        return await _teams_page(
            request,
            session,
            settings,
            user,
            name=name[:100],
            errors=validation_messages(exc),
            status_code=422,
        )
    except TeamNameTaken as exc:
        return await _teams_page(
            request,
            session,
            settings,
            user,
            name=name[:100],
            errors=[exc.detail],
            status_code=exc.status_code,
        )
    return see_other(f"/teams/{team.id}")


# --- One team ------------------------------------------------------------------------------------


async def _team_page(
    request: Request,
    session: DbSession,
    settings: Settings,
    user: CurrentUser,
    team_id: IntId,
    *,
    page: int = 1,
    notice: str | None = None,
    errors: list[str] | None = None,
    username: str = "",
    status_code: int = 200,
) -> Response:
    """Render ``team_detail.html``: members, shared files and the owner's forms.

    Raises:
        NotFound: the team does not exist or the user is not a member.
    """
    detail = await teams.get_team(session, user, team_id)
    items, total = await teams.list_team_files(
        session, user, team_id, page=page, size=FILES_PER_PAGE
    )
    return render_page(
        request,
        settings,
        user,
        "team_detail.html",
        {
            "team": detail.team,
            "members": detail.members,
            "files": [file_out(item, user.id) for item in items],
            "page": page,
            "pages": max(1, -(-total // FILES_PER_PAGE)),
            "total": total,
            "is_owner": can_manage_members(user, detail.team),
            "can_delete": can_delete_team(user, detail.team),
            "notice": notice,
            "errors": errors or [],
            "username": username,
        },
        status_code=status_code,
    )


@router.get("/teams/{team_id}")
@limit("read")
async def team_page(
    request: Request,
    team_id: IntId,
    user: PageUser,
    session: DbSession,
    settings: SettingsDep,
    page: PageNumber = 1,
    added: bool = False,
) -> Response:
    """Show a team to its members: members, shared files and (for the owner) management."""
    notice = MEMBER_ADD_NOTICE if added else None
    return await _team_page(request, session, settings, user, team_id, page=page, notice=notice)


@router.post("/teams/{team_id}/delete", dependencies=[CsrfChecked])
@limit("write")
async def delete_team_submit(
    request: Request, team_id: IntId, user: PageUser, ctx: PageAuditCtx, session: DbSession
) -> Response:
    """Delete the team (owner or admin) and go back to the team list."""
    await teams.delete_team(session, user, team_id, ctx)
    return see_other("/teams")


@router.post("/teams/{team_id}/members", dependencies=[CsrfChecked])
@limit("write")
async def add_member_submit(
    request: Request,
    team_id: IntId,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    settings: SettingsDep,
    username: Annotated[str, Form()] = "",
) -> Response:
    """Add a member by username (owner). Always the same notice, whether or not it existed."""
    try:
        form = AddMemberIn.model_validate({"username": username})
    except ValidationError as exc:
        # Only the format is checked here, so the message reveals nothing about accounts.
        return await _team_page(
            request,
            session,
            settings,
            user,
            team_id,
            errors=validation_messages(exc),
            username=username.strip().lower()[:32],
            status_code=422,
        )
    await teams.add_member(session, user, team_id, form.username, ctx)
    return see_other(f"/teams/{team_id}?added=1")


@router.post("/teams/{team_id}/members/{member_id}/remove", dependencies=[CsrfChecked])
@limit("write")
async def remove_member_submit(
    request: Request,
    team_id: IntId,
    member_id: IntId,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
) -> Response:
    """Remove a member (owner) or leave the team (the member themself)."""
    await teams.remove_member(session, user, team_id, member_id, ctx)
    # Somebody who left can no longer see the team page.
    return see_other("/teams" if member_id == user.id else f"/teams/{team_id}")
