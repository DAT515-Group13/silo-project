"""Teams, memberships and the sharing helpers for B.

Every public service function owns its transaction and writes its audit entry. The three helpers
at the end (``is_team_member``, ``is_shared_with_user``, ``shared_file_ids_for_user``) are
building blocks for the file services and run in the caller's transaction.

Missing access is always ``NotFound``, so a non-member cannot tell whether a team
exists. Only team creation by a plain ``user`` is ``RoleRequired`` (D19).
"""

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Select, delete, exists, literal, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.errors import NotFound, OwnerCannotLeave, RoleRequired, TeamNameTaken
from app.models import File, FileShare, Team, TeamMember, User, UserStatus
from app.permissions import (
    CurrentUser,
    can_create_team,
    can_delete_team,
    can_manage_members,
    can_remove_member,
    can_view_team,
)
from app.services import audit
from app.services.audit import AuditAction, AuditContext
from app.services.pagination import fetch_page


@dataclass(frozen=True)
class Member:
    """A member of a team, as shown in the team details."""

    user_id: int
    username: str
    added_at: datetime


@dataclass(frozen=True)
class TeamDetail:
    """A team with its members (``GET /teams/{id}``)."""

    team: Team
    members: list[Member]


@dataclass(frozen=True)
class FileItem:
    """A file row with its owner's username, for file listings (example 9.3)."""

    file: File
    owner_username: str


# --- Helpers for the file services (B) -----------------------------------------------------------


async def is_team_member(session: AsyncSession, team_id: int, user_id: int) -> bool:
    """True if the user is a member of the team. Caller's transaction (open it first)."""
    return bool(
        await session.scalar(
            select(exists().where(TeamMember.team_id == team_id, TeamMember.user_id == user_id))
        )
    )


def shared_file_ids_for_user(user_id: int) -> Select[tuple[uuid.UUID]]:
    """Subquery of the IDs of files shared with any team the user belongs to ("Shared with me").

    Use it as ``File.id.in_(shared_file_ids_for_user(user.id))``. Access is computed per
    request from the memberships, so leaving a team ends access immediately.
    """
    return (
        select(FileShare.file_id)
        .join(TeamMember, TeamMember.team_id == FileShare.team_id)
        .where(TeamMember.user_id == user_id)
    )


async def is_shared_with_user(session: AsyncSession, file_id: uuid.UUID, user_id: int) -> bool:
    """True if the file is shared with a team the user belongs to. Caller's transaction."""
    shares = shared_file_ids_for_user(user_id).where(FileShare.file_id == file_id)
    return bool(await session.scalar(select(exists(shares))))


# --- Internal ------------------------------------------------------------------------------------


async def _load_team(session: AsyncSession, team_id: int, *, lock: bool = False) -> Team:
    """Load a team or raise ``NotFound``. ``lock`` takes a row lock for changes."""
    statement = select(Team).where(Team.id == team_id)
    if lock:
        # populate_existing: re-read the locked row even if the session holds an older copy.
        statement = statement.with_for_update().execution_options(populate_existing=True)
    team = await session.scalar(statement)
    if team is None:
        raise NotFound
    return team


async def _require_member(session: AsyncSession, user: CurrentUser, team_id: int) -> Team:
    """Load a team the user may see (members only), else ``NotFound``."""
    team = await _load_team(session, team_id)
    # Permission check: a non-member gets the same 404 as for a team that does not exist.
    if not can_view_team(is_member=await is_team_member(session, team_id, user.id)):
        raise NotFound
    return team


# --- Teams ---------------------------------------------------------------------------------------


async def create_team(
    session: AsyncSession, user: CurrentUser, name: str, ctx: AuditContext
) -> Team:
    """Create a team owned by ``user``, who also becomes its first member (POST /teams).

    ``name`` is already trimmed and 1-100 characters long (schema ``TeamName``).

    Raises:
        RoleRequired: the user is neither ``team_lead`` nor ``admin`` (D19).
        TeamNameTaken: the user already owns a team with this name (D18).

    Side effects: inserts the team and the membership, writes ``team.create``.
    """
    # Permission check: the role decides, and it is read from the database.
    if not can_create_team(user):
        raise RoleRequired

    async with session.begin():
        # ON CONFLICT on the (owner_id, name) constraint: two parallel requests with the same
        # name cannot both succeed, and the loser gets a clean 409 instead of an error 500.
        team_id = await session.scalar(
            pg_insert(Team)
            .values(name=name, owner_id=user.id)
            .on_conflict_do_nothing(constraint="uq_teams_owner_id_name")
            .returning(Team.id)
        )
        if team_id is None:
            raise TeamNameTaken
        session.add(TeamMember(team_id=team_id, user_id=user.id))
        await audit.record(
            session,
            ctx,
            AuditAction.team_create,
            target_type="team",
            target_id=team_id,
            target_label=name,
        )
        return await session.get_one(Team, team_id)


async def list_my_teams(session: AsyncSession, user: CurrentUser) -> list[Team]:
    """Teams the user belongs to, by name (GET /teams). Owns its read-only transaction."""
    async with session.begin():
        result = await session.scalars(
            select(Team)
            .join(TeamMember, TeamMember.team_id == Team.id)
            .where(TeamMember.user_id == user.id)
            .order_by(Team.name, Team.id)
        )
        return list(result)


async def get_team(session: AsyncSession, user: CurrentUser, team_id: int) -> TeamDetail:
    """A team and its members, for members only (GET /teams/{id}).

    Raises:
        NotFound: the team does not exist or the user is not a member.
    """
    async with session.begin():
        team = await _require_member(session, user, team_id)
        rows = await session.execute(
            select(TeamMember.user_id, User.username, TeamMember.added_at)
            .join(User, User.id == TeamMember.user_id)
            .where(TeamMember.team_id == team_id)
            .order_by(User.username)
        )
        members = [Member(row.user_id, row.username, row.added_at) for row in rows]
    return TeamDetail(team=team, members=members)


async def delete_team(
    session: AsyncSession, user: CurrentUser, team_id: int, ctx: AuditContext
) -> None:
    """Delete a team; memberships and file shares go with it, files stay.

    Raises:
        NotFound: the team does not exist, or the user is neither its owner nor an admin.

    Side effects: deletes the team, writes ``team.delete``.
    """
    async with session.begin():
        team = await _load_team(session, team_id, lock=True)
        # Permission check: owner or admin; everybody else gets the 404 of a missing team.
        if not can_delete_team(user, team):
            raise NotFound
        await session.execute(delete(Team).where(Team.id == team_id))
        await audit.record(
            session,
            ctx,
            AuditAction.team_delete,
            target_type="team",
            target_id=team_id,
            target_label=team.name,
        )


async def list_team_files(
    session: AsyncSession, user: CurrentUser, team_id: int, *, page: int, size: int
) -> tuple[list[FileItem], int]:
    """Files shared with the team, newest first (GET /teams/{id}/files). Members only.

    Returns the items of the page and the total count.

    Raises:
        NotFound: the team does not exist or the user is not a member.
    """
    async with session.begin():
        await _require_member(session, user, team_id)
        statement = (
            select(File, User.username)
            .join(FileShare, FileShare.file_id == File.id)
            .join(User, User.id == File.owner_id)
            .where(FileShare.team_id == team_id)
            .order_by(File.created_at.desc(), File.id)
        )
        rows, total = await fetch_page(session, statement, page=page, size=size)
    return [FileItem(file=row[0], owner_username=row[1]) for row in rows], total


# --- Members -------------------------------------------------------------------------------------


async def add_member(
    session: AsyncSession, user: CurrentUser, team_id: int, username: str, ctx: AuditContext
) -> None:
    """Add an active account to the team (POST /teams/{id}/members). Team owner only.

    The result is **the same** whether the username is unknown, belongs to an account that is
    not active, is already a member or was added (no enumeration). ``username`` is
    already normalized by the schema.

    Raises:
        NotFound: the team does not exist or the user is not its owner.

    Side effects: inserts the membership and writes ``team.member_add`` only if it was added.
    """
    async with session.begin():
        # Locked: a parallel delete_team then finishes first and this request gets the 404 of
        # a missing team, instead of a foreign key error (500) on the insert below.
        team = await _load_team(session, team_id, lock=True)
        # Permission check: only the owner adds members (not even an admin).
        if not can_manage_members(user, team):
            raise NotFound

        # One statement for every case, so neither the answer nor its timing depends on
        # whether the account exists: unknown or inactive names select no row, an existing
        # membership hits the primary key and is skipped.
        candidate = select(literal(team_id), User.id).where(
            User.username == username, User.status == UserStatus.active
        )
        added = await session.scalar(
            pg_insert(TeamMember)
            .from_select(["team_id", "user_id"], candidate)
            .on_conflict_do_nothing()
            .returning(TeamMember.user_id)
        )
        if added is not None:
            await audit.record(
                session,
                ctx,
                AuditAction.team_member_add,
                target_type="team",
                target_id=team_id,
                target_label=team.name,
                details={"user_id": added, "username": username},
            )


async def remove_member(
    session: AsyncSession,
    user: CurrentUser,
    team_id: int,
    member_id: int,
    ctx: AuditContext,
) -> None:
    """Remove a member, or leave the team (DELETE /teams/{id}/members/{user_id}).

    The owner may remove anybody but themself; a member may remove only themself. The removed
    user's shares of their own files with this team are deleted in the same transaction, so
    their files stop being visible to the team at once.

    Raises:
        NotFound: the team does not exist, the caller may not remove this user, or the user is
            not a member (Q22).
        OwnerCannotLeave: the owner tried to remove themself.

    Side effects: deletes the membership and the shares, writes ``team.member_remove``.
    """
    async with session.begin():
        team = await _load_team(session, team_id, lock=True)
        # Permission check: the owner, or the member themself; others get a 404.
        if not can_remove_member(user, team, member_id):
            raise NotFound
        # Business rule: the owner can only delete the team, never leave it.
        if member_id == team.owner_id:
            raise OwnerCannotLeave

        removed = await session.scalar(
            delete(TeamMember)
            .where(TeamMember.team_id == team_id, TeamMember.user_id == member_id)
            .returning(TeamMember.user_id)
        )
        if removed is None:
            raise NotFound

        # Shares are made by file owners, so only this user's own files leave the team.
        own_files = select(File.id).where(File.owner_id == member_id)
        shares = await session.execute(
            delete(FileShare)
            .where(FileShare.team_id == team_id, FileShare.file_id.in_(own_files))
            .returning(FileShare.file_id)
        )
        await audit.record(
            session,
            ctx,
            AuditAction.team_member_remove,
            target_type="team",
            target_id=team_id,
            target_label=team.name,
            details={
                "user_id": member_id,
                "left": member_id == user.id,
                "shares_removed": len(shares.all()),
            },
        )
