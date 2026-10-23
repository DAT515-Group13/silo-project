"""Object-level access rules as pure functions.

Nothing in this module reads or writes the database: services load the facts (the file or team
row, membership, shares) and pass them in. Callers turn ``False`` into ``NotFound`` (404, never
403), so object IDs cannot be probed. The one exception is ``can_create_team``: it
is about the caller's role, not about an object, and maps to ``RoleRequired`` (403, D19).
"""

import uuid
from dataclasses import dataclass

from app.models import File, Role, Team


@dataclass(frozen=True)
class CurrentUser:
    """The authenticated user of a request. Role and status are read from the database.

    It lives here, not in the routers, because services take it as an argument and must not
    import anything from the HTTP layer.
    """

    id: int
    username: str
    role: Role
    session_id: uuid.UUID


# --- Roles ---------------------------------------------------------------------------------------


def is_admin(user: CurrentUser) -> bool:
    """True for the ``admin`` role. Non-admins get 404 on every admin endpoint."""
    return user.role == Role.admin


# --- Files ---------------------------------------------------------------------


def _is_file_owner(user: CurrentUser, file: File) -> bool:
    return file.owner_id == user.id


def can_view_file(user: CurrentUser, file: File, *, shared_with_user: bool) -> bool:
    """See a file's metadata: the owner, or a member of a team the file is shared with.

    ``shared_with_user`` is True if the file is shared with at least one team the user belongs
    to (``services.teams.is_shared_with_user``). Admins see all files only through
    ``/admin/files``, which checks ``is_admin`` instead of this function.
    """
    return _is_file_owner(user, file) or shared_with_user


def can_download_file(user: CurrentUser, file: File, *, shared_with_user: bool) -> bool:
    """Download a file: the owner or a team member. Never an admin as such (privacy).

    An admin who owns the file, or is in a team it is shared with, may download it like anybody
    else; the admin role itself grants nothing here.
    """
    return _is_file_owner(user, file) or shared_with_user


def can_modify_file(user: CurrentUser, file: File) -> bool:
    """Rename a file, share or unshare it, create links: the owner only."""
    return _is_file_owner(user, file)


def can_delete_file(user: CurrentUser, file: File) -> bool:
    """Delete a file: the owner or an admin. Team members never."""
    return _is_file_owner(user, file) or is_admin(user)


def can_share_with_team(user: CurrentUser, file: File, *, user_is_member: bool) -> bool:
    """Share a file with a team: the owner, and only with a team they belong to.

    ``user_is_member`` is the owner's membership in the target team
    (``services.teams.is_team_member``).
    """
    return can_modify_file(user, file) and user_is_member


def can_revoke_link(user: CurrentUser, file: File) -> bool:
    """Revoke a public link of ``file``: the file owner or an admin."""
    return _is_file_owner(user, file) or is_admin(user)


# --- Teams --------------------------------------------------------------


def can_create_team(user: CurrentUser) -> bool:
    """Create a team: ``team_lead`` or ``admin``.

    Only creation depends on the role. A team lead demoted to ``user`` keeps managing the teams
    they own, because every other team rule looks at ownership, not at the role.
    The caller answers ``False`` with ``RoleRequired`` (403, D19), not with 404.
    """
    return user.role in (Role.team_lead, Role.admin)


def can_view_team(*, is_member: bool) -> bool:
    """See a team, its members and its files: members only. The owner is always a member."""
    return is_member


def can_delete_team(user: CurrentUser, team: Team) -> bool:
    """Delete a team: its owner or an admin."""
    return team.owner_id == user.id or is_admin(user)


def can_manage_members(user: CurrentUser, team: Team) -> bool:
    """Add members to a team: its owner only. Admins have no special right here."""
    return team.owner_id == user.id


def can_remove_member(user: CurrentUser, team: Team, target_user_id: int) -> bool:
    """Remove a member: the team owner, or the member removing themself (leaving).

    This only answers "may this user ask for it". Whether it is allowed in this state is a
    business rule of the service: the owner can never leave (``OwnerCannotLeave``).
    """
    return team.owner_id == user.id or target_user_id == user.id
