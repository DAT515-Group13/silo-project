"""Permission matrix and the team rules.

The rules are pure functions, so no database is needed: the facts a service would load
(ownership, membership, shares) are passed in directly.
"""

import uuid

import pytest

from app.models import File, Role, Team
from app.permissions import (
    CurrentUser,
    can_create_team,
    can_delete_file,
    can_delete_team,
    can_download_file,
    can_manage_members,
    can_modify_file,
    can_remove_member,
    can_revoke_link,
    can_share_with_team,
    can_view_file,
    can_view_team,
    is_admin,
)

OWNER_ID, MEMBER_ID, ADMIN_ID, STRANGER_ID = 1, 2, 3, 4


def make_user(user_id: int, role: Role = Role.user) -> CurrentUser:
    return CurrentUser(id=user_id, username=f"user{user_id}", role=role, session_id=uuid.uuid4())


# Who is asking, and whether the file is shared with a team they belong to.
ACTORS = {
    "owner": (make_user(OWNER_ID), False),
    "team_member": (make_user(MEMBER_ID), True),
    "admin": (make_user(ADMIN_ID, Role.admin), False),
    "stranger": (make_user(STRANGER_ID), False),
}

FILE = File(id=uuid.uuid4(), owner_id=OWNER_ID, filename="report.pdf", blob_name="b")
TEAM = Team(id=10, name="Team", owner_id=OWNER_ID)


# --- Files: one test per cell of the permission matrix -------------------------------------------


@pytest.mark.parametrize(
    ("actor", "allowed"),
    [("owner", True), ("team_member", True), ("admin", False), ("stranger", False)],
)
def test_see_in_lists(actor: str, allowed: bool) -> None:
    """Owner and team member see the file; admins only via /admin/files; others get 404."""
    user, shared = ACTORS[actor]
    assert can_view_file(user, FILE, shared_with_user=shared) is allowed


@pytest.mark.parametrize(
    ("actor", "allowed"),
    [("owner", True), ("team_member", True), ("admin", False), ("stranger", False)],
)
def test_download(actor: str, allowed: bool) -> None:
    """Owner and team member download; an admin does not (privacy)."""
    user, shared = ACTORS[actor]
    assert can_download_file(user, FILE, shared_with_user=shared) is allowed


@pytest.mark.parametrize(
    ("actor", "allowed"),
    [("owner", True), ("team_member", False), ("admin", True), ("stranger", False)],
)
def test_delete(actor: str, allowed: bool) -> None:
    """Owner and admin delete; a team member cannot delete a shared file."""
    user, _ = ACTORS[actor]
    assert can_delete_file(user, FILE) is allowed


@pytest.mark.parametrize(
    ("actor", "allowed"),
    [("owner", True), ("team_member", False), ("admin", False), ("stranger", False)],
)
def test_rename_share_and_create_links(actor: str, allowed: bool) -> None:
    """Rename, share and create links: the owner only, not even an admin."""
    user, _ = ACTORS[actor]
    assert can_modify_file(user, FILE) is allowed
    assert can_share_with_team(user, FILE, user_is_member=True) is allowed


@pytest.mark.parametrize(
    ("actor", "allowed"),
    [("owner", True), ("team_member", False), ("admin", True), ("stranger", False)],
)
def test_revoke_link(actor: str, allowed: bool) -> None:
    """A link is revoked by the file owner or an admin."""
    user, _ = ACTORS[actor]
    assert can_revoke_link(user, FILE) is allowed


def test_admin_who_is_a_team_member_downloads_like_a_member() -> None:
    """The admin role grants no download, but it does not take membership rights away."""
    admin, _ = ACTORS["admin"]
    assert can_download_file(admin, FILE, shared_with_user=True)


def test_owner_shares_only_with_own_teams() -> None:
    """Sharing works only with a team the owner belongs to."""
    owner, _ = ACTORS["owner"]
    assert not can_share_with_team(owner, FILE, user_is_member=False)


def test_is_admin() -> None:
    """Only the admin role is admin; team_lead is not."""
    assert is_admin(make_user(1, Role.admin))
    assert not is_admin(make_user(1, Role.team_lead))
    assert not is_admin(make_user(1, Role.user))


# --- Teams ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "allowed"), [(Role.user, False), (Role.team_lead, True), (Role.admin, True)]
)
def test_create_team_needs_team_lead_or_admin(role: Role, allowed: bool) -> None:
    """Only team_lead and admin create teams."""
    assert can_create_team(make_user(1, role)) is allowed


def test_demoted_team_lead_keeps_managing_own_team() -> None:
    """A team_lead demoted to user cannot create teams but still manages theirs."""
    demoted = make_user(OWNER_ID, Role.user)
    assert not can_create_team(demoted)
    assert can_manage_members(demoted, TEAM)
    assert can_delete_team(demoted, TEAM)


def test_only_members_see_a_team() -> None:
    """Team details and team files are for members only; everybody else gets 404."""
    assert can_view_team(is_member=True)
    assert not can_view_team(is_member=False)


@pytest.mark.parametrize(
    ("actor", "allowed"),
    [("owner", True), ("team_member", False), ("admin", True), ("stranger", False)],
)
def test_delete_team(actor: str, allowed: bool) -> None:
    """A team is deleted by its owner or an admin."""
    user, _ = ACTORS[actor]
    assert can_delete_team(user, TEAM) is allowed


@pytest.mark.parametrize(
    ("actor", "allowed"),
    [("owner", True), ("team_member", False), ("admin", False), ("stranger", False)],
)
def test_add_members(actor: str, allowed: bool) -> None:
    """Only the team owner adds members; the admin role gives no right here."""
    user, _ = ACTORS[actor]
    assert can_manage_members(user, TEAM) is allowed


def test_remove_member_by_owner_or_self() -> None:
    """The owner removes anyone; a member may remove only themself (leave)."""
    owner, _ = ACTORS["owner"]
    member, _ = ACTORS["team_member"]
    stranger, _ = ACTORS["stranger"]
    assert can_remove_member(owner, TEAM, MEMBER_ID)
    assert can_remove_member(member, TEAM, MEMBER_ID)
    assert not can_remove_member(member, TEAM, STRANGER_ID)
    assert not can_remove_member(stranger, TEAM, MEMBER_ID)
