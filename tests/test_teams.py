"""Teams and members.

Tests without the ``db`` marker stop before the database (role check, validation). The ``db``
tests go through HTTP with real tokens.
"""

import httpx
import pytest
from sqlalchemy import func, select, update

from app.models import AuditLog, File, FileShare, Role, TeamMember, User, UserStatus
from tests.conftest import (
    ActAs,
    BearerFor,
    FileFactory,
    Sessionmaker,
    UserFactory,
    add_member,
    make_team,
)

pytestmark = pytest.mark.anyio


# --- No database needed --------------------------------------------------------------------------


async def test_plain_user_cannot_create_a_team(client: httpx.AsyncClient, act_as: ActAs) -> None:
    """Only team_lead and admin create teams; a user gets 403 role_required (D19)."""
    act_as(Role.user)
    response = await client.post("/api/v1/teams", json={"name": "Design"})
    assert response.status_code == 403
    assert response.json()["code"] == "role_required"


async def test_add_member_validates_the_username(client: httpx.AsyncClient, act_as: ActAs) -> None:
    """The add-member body follows the username rule; format errors are 422."""
    act_as(Role.team_lead)
    response = await client.post("/api/v1/teams/1/members", json={"username": "-bad"})
    assert response.status_code == 422


async def test_team_endpoints_need_a_token(client: httpx.AsyncClient) -> None:
    """Without a Bearer token a team endpoint is 401 invalid_token."""
    response = await client.get("/api/v1/teams/1")
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


# --- Needs PostgreSQL ----------------------------------------------------------------------------


async def member_names(client: httpx.AsyncClient, headers: dict, team_id: int) -> list[str]:
    response = await client.get(f"/api/v1/teams/{team_id}", headers=headers)
    assert response.status_code == 200, response.text
    return [m["username"] for m in response.json()["members"]]


@pytest.mark.db
async def test_lead_creates_a_team_and_becomes_owner_and_member(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The creator owns the team and is its first member; team.create is audited."""
    lead = await user_factory(username="lead", role=Role.team_lead)
    headers = await bearer_for(lead)
    team_id = await make_team(client, headers, "  Design  ")

    listing = await client.get("/api/v1/teams", headers=headers)
    assert [(t["id"], t["name"], t["owner_id"]) for t in listing.json()] == [
        (team_id, "Design", lead.id)
    ]
    assert await member_names(client, headers, team_id) == ["lead"]
    async with db_sessionmaker() as session, session.begin():
        actions = (await session.scalars(select(AuditLog.action))).all()
    assert "team.create" in actions


@pytest.mark.db
async def test_team_names_are_unique_per_owner(
    client: httpx.AsyncClient, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """The same owner cannot reuse a name (409 team_name_taken); another owner can (s. 11)."""
    first = await bearer_for(await user_factory(username="lead", role=Role.team_lead))
    second = await bearer_for(await user_factory(username="other", role=Role.team_lead))
    await make_team(client, first, "Design")
    again = await client.post("/api/v1/teams", json={"name": "Design"}, headers=first)
    assert again.status_code == 409
    assert again.json()["code"] == "team_name_taken"
    await make_team(client, second, "Design")


@pytest.mark.db
async def test_non_members_get_404_everywhere(
    client: httpx.AsyncClient, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """A stranger cannot see, list files of, delete or change a team: always 404."""
    owner = await bearer_for(await user_factory(username="lead", role=Role.team_lead))
    stranger = await bearer_for(await user_factory(username="eve"))
    team_id = await make_team(client, owner)

    assert (await client.get(f"/api/v1/teams/{team_id}", headers=stranger)).status_code == 404
    files = await client.get(f"/api/v1/teams/{team_id}/files", headers=stranger)
    assert files.status_code == 404
    assert (await client.delete(f"/api/v1/teams/{team_id}", headers=stranger)).status_code == 404
    assert await add_member(client, stranger, team_id, "eve") == 404
    assert (await client.get("/api/v1/teams/999999", headers=stranger)).status_code == 404


@pytest.mark.db
async def test_add_member_always_answers_204(
    client: httpx.AsyncClient, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """Unknown, pending, existing and new usernames all give 204; only active accounts join.

    No enumeration on add-member.
    """
    owner = await bearer_for(await user_factory(username="lead", role=Role.team_lead))
    await user_factory(username="anna")
    await user_factory(username="pending1", status=UserStatus.pending)
    await user_factory(username="gone", status=UserStatus.disabled)
    team_id = await make_team(client, owner)

    for username in ("nobody", "pending1", "gone", "anna", "anna", "ANNA"):
        assert await add_member(client, owner, team_id, username) == 204
    assert await member_names(client, owner, team_id) == ["anna", "lead"]


@pytest.mark.db
async def test_only_the_owner_adds_members(
    client: httpx.AsyncClient, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """A member, and even an admin, cannot add members to someone else's team (s. 8.1)."""
    owner = await bearer_for(await user_factory(username="lead", role=Role.team_lead))
    member_user = await user_factory(username="anna")
    member = await bearer_for(member_user)
    admin = await bearer_for(await user_factory(username="root", role=Role.admin))
    await user_factory(username="bob")
    team_id = await make_team(client, owner)
    await add_member(client, owner, team_id, "anna")

    assert await add_member(client, member, team_id, "bob") == 404
    assert await add_member(client, admin, team_id, "bob") == 404
    assert await member_names(client, owner, team_id) == ["anna", "lead"]


@pytest.mark.db
async def test_owner_cannot_leave_but_members_can(
    client: httpx.AsyncClient, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """The owner leaving is 409 owner_cannot_leave; a member may leave."""
    lead = await user_factory(username="lead", role=Role.team_lead)
    owner = await bearer_for(lead)
    anna = await user_factory(username="anna")
    member = await bearer_for(anna)
    team_id = await make_team(client, owner)
    await add_member(client, owner, team_id, "anna")

    leave_owner = await client.delete(f"/api/v1/teams/{team_id}/members/{lead.id}", headers=owner)
    assert leave_owner.status_code == 409
    assert leave_owner.json()["code"] == "owner_cannot_leave"

    leave = await client.delete(f"/api/v1/teams/{team_id}/members/{anna.id}", headers=member)
    assert leave.status_code == 204
    assert await member_names(client, owner, team_id) == ["lead"]
    # Gone means gone: the former member now gets 404, and a second removal is 404 (Q22).
    assert (await client.get(f"/api/v1/teams/{team_id}", headers=member)).status_code == 404
    again = await client.delete(f"/api/v1/teams/{team_id}/members/{anna.id}", headers=owner)
    assert again.status_code == 404


@pytest.mark.db
async def test_a_member_cannot_remove_another_member(
    client: httpx.AsyncClient, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """Members may remove only themselves; the owner removes anyone else."""
    owner = await bearer_for(await user_factory(username="lead", role=Role.team_lead))
    anna = await user_factory(username="anna")
    bob = await user_factory(username="bob")
    team_id = await make_team(client, owner)
    await add_member(client, owner, team_id, "anna")
    await add_member(client, owner, team_id, "bob")

    by_anna = await client.delete(
        f"/api/v1/teams/{team_id}/members/{bob.id}", headers=await bearer_for(anna)
    )
    assert by_anna.status_code == 404
    by_owner = await client.delete(f"/api/v1/teams/{team_id}/members/{bob.id}", headers=owner)
    assert by_owner.status_code == 204


@pytest.mark.db
async def test_leaving_removes_only_the_leavers_shares(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
    file_factory: FileFactory,
) -> None:
    """Leaving deletes the leaver's shares with that team in the same step."""
    lead = await user_factory(username="lead", role=Role.team_lead)
    owner = await bearer_for(lead)
    anna = await user_factory(username="anna")
    team_id = await make_team(client, owner)
    await add_member(client, owner, team_id, "anna")
    await file_factory(anna.id, team_id)
    leads_file = (await file_factory(lead.id, team_id)).id

    files = await client.get(f"/api/v1/teams/{team_id}/files", headers=owner)
    assert files.json()["total"] == 2

    await client.delete(f"/api/v1/teams/{team_id}/members/{anna.id}", headers=owner)
    async with db_sessionmaker() as session, session.begin():
        shared = set((await session.scalars(select(FileShare.file_id))).all())
    assert shared == {leads_file}


@pytest.mark.db
async def test_team_files_list_is_paginated_and_marks_own_files(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
) -> None:
    """Members see shared files with owner and is_owner, in pages (example 9.3)."""
    lead = await user_factory(username="lead", role=Role.team_lead)
    owner = await bearer_for(lead)
    anna = await user_factory(username="anna")
    team_id = await make_team(client, owner)
    await add_member(client, owner, team_id, "anna")
    for _ in range(3):
        await file_factory(lead.id, team_id)
    await file_factory(lead.id)  # not shared

    page = await client.get(
        f"/api/v1/teams/{team_id}/files?page=2&size=2", headers=await bearer_for(anna)
    )
    body = page.json()
    assert (body["total"], body["page"], body["size"], len(body["items"])) == (3, 2, 2, 1)
    item = body["items"][0]
    assert item["owner"] == {"id": lead.id, "username": "lead"}
    assert item["is_owner"] is False
    assert "blob_name" not in item


@pytest.mark.db
async def test_demoted_lead_keeps_managing_own_team(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """A team_lead demoted to user keeps the team but cannot create new ones."""
    lead = await user_factory(username="lead", role=Role.team_lead)
    owner = await bearer_for(lead)
    await user_factory(username="anna")
    team_id = await make_team(client, owner)
    async with db_sessionmaker() as session, session.begin():
        await session.execute(update(User).where(User.id == lead.id).values(role=Role.user))

    assert await add_member(client, owner, team_id, "anna") == 204
    assert await member_names(client, owner, team_id) == ["anna", "lead"]
    new = await client.post("/api/v1/teams", json={"name": "Other"}, headers=owner)
    assert new.status_code == 403


@pytest.mark.db
async def test_owner_and_admin_delete_a_team_but_members_cannot(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
    file_factory: FileFactory,
) -> None:
    """Team owner or admin delete; memberships and shares go, files stay."""
    lead = await user_factory(username="lead", role=Role.team_lead)
    owner = await bearer_for(lead)
    member = await bearer_for(await user_factory(username="anna"))
    admin = await bearer_for(await user_factory(username="root", role=Role.admin))
    team_id = await make_team(client, owner)
    await add_member(client, owner, team_id, "anna")
    await file_factory(lead.id, team_id)

    assert (await client.delete(f"/api/v1/teams/{team_id}", headers=member)).status_code == 404
    assert (await client.delete(f"/api/v1/teams/{team_id}", headers=admin)).status_code == 204
    async with db_sessionmaker() as session, session.begin():
        memberships = await session.scalar(select(func.count()).select_from(TeamMember))
        shares = await session.scalar(select(func.count()).select_from(FileShare))
        files = await session.scalar(select(func.count()).select_from(File))
    assert (memberships, shares, files) == (0, 0, 1)
