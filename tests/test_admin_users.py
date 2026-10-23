"""Admin user management.

Tests without the ``db`` marker stop at the admin check or at validation. The ``db`` tests go
through HTTP with real tokens.
"""

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import AuditLog, Role, Team, User, UserStatus
from tests.conftest import ActAs, BearerFor, FileFactory, UserFactory
from tests.fakes import InMemoryBlobStore

pytestmark = pytest.mark.anyio

Sessionmaker = async_sessionmaker[AsyncSession]

ADMIN_ROUTES = [
    ("GET", "/api/v1/admin/users", None),
    ("POST", "/api/v1/admin/users/2/approve", None),
    ("POST", "/api/v1/admin/users/2/reject", None),
    ("PATCH", "/api/v1/admin/users/2", {"role": "admin"}),
    ("POST", "/api/v1/admin/users/2/revoke-sessions", None),
    ("DELETE", "/api/v1/admin/users/2", None),
    ("GET", "/api/v1/admin/files", None),
    ("GET", "/api/v1/admin/audit", None),
]


# --- No database needed --------------------------------------------------------------------------


@pytest.mark.parametrize("role", [Role.user, Role.team_lead])
@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ROUTES)
async def test_non_admins_get_404_on_every_admin_endpoint(
    client: httpx.AsyncClient, act_as: ActAs, role: Role, method: str, path: str, body: dict | None
) -> None:
    """The admin area does not exist for non-admins: 404, not 403."""
    act_as(role)
    response = await client.request(method, path, json=body)
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"


@pytest.mark.parametrize("body", [{"status": "pending"}, {"status": "rejected"}, {"x": 1}])
async def test_patch_only_switches_between_active_and_disabled(
    client: httpx.AsyncClient, act_as: ActAs, body: dict
) -> None:
    """PATCH accepts status active or disabled only, and no unknown fields."""
    act_as(Role.admin)
    response = await client.patch("/api/v1/admin/users/2", json=body)
    assert response.status_code == 422


# --- Needs PostgreSQL ----------------------------------------------------------------------------


async def status_of(sm: Sessionmaker, user_id: int) -> tuple[Role, UserStatus] | None:
    async with sm() as session, session.begin():
        row = (
            await session.execute(select(User.role, User.status).where(User.id == user_id))
        ).first()
    return None if row is None else (row.role, row.status)


async def actions(sm: Sessionmaker) -> list[str]:
    async with sm() as session, session.begin():
        return list(await session.scalars(select(AuditLog.action).order_by(AuditLog.id)))


@pytest.fixture
async def root(user_factory: UserFactory) -> User:
    return await user_factory(username="root", role=Role.admin)


@pytest.mark.db
async def test_list_users_filters_by_status_and_counts_files(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
) -> None:
    """The list shows status and file count (for the delete warning)."""
    anna = await user_factory(username="anna")
    await user_factory(username="newbie", status=UserStatus.pending)
    await file_factory(anna.id)
    await file_factory(anna.id)
    headers = await bearer_for(root)

    everyone = (await client.get("/api/v1/admin/users", headers=headers)).json()
    assert everyone["total"] == 3
    counts = {item["username"]: item["file_count"] for item in everyone["items"]}
    assert counts == {"root": 0, "anna": 2, "newbie": 0}
    assert all("password_hash" not in item for item in everyone["items"])

    pending = (await client.get("/api/v1/admin/users?status=pending", headers=headers)).json()
    assert [item["username"] for item in pending["items"]] == ["newbie"]


@pytest.mark.db
async def test_approve_only_pending_accounts(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """pending -> active, audited; approving again is 409 invalid_user_state (D18)."""
    newbie = await user_factory(username="newbie", status=UserStatus.pending)
    headers = await bearer_for(root)

    first = await client.post(f"/api/v1/admin/users/{newbie.id}/approve", headers=headers)
    assert first.status_code == 204
    assert await status_of(db_sessionmaker, newbie.id) == (Role.user, UserStatus.active)
    again = await client.post(f"/api/v1/admin/users/{newbie.id}/approve", headers=headers)
    assert (again.status_code, again.json()["code"]) == (409, "invalid_user_state")
    assert "user.approve" in await actions(db_sessionmaker)

    async with db_sessionmaker() as session, session.begin():
        approved_by = await session.scalar(select(User.approved_by).where(User.id == newbie.id))
    assert approved_by == root.id


@pytest.mark.db
async def test_reject_a_pending_account_with_a_reason(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """pending -> rejected with the reason in the audit entry; active accounts give 409."""
    newbie = await user_factory(username="newbie", status=UserStatus.pending)
    anna = await user_factory(username="anna")
    headers = await bearer_for(root)

    response = await client.post(
        f"/api/v1/admin/users/{newbie.id}/reject", json={"reason": "unknown"}, headers=headers
    )
    assert response.status_code == 204
    assert await status_of(db_sessionmaker, newbie.id) == (Role.user, UserStatus.rejected)
    async with db_sessionmaker() as session, session.begin():
        details = await session.scalar(
            select(AuditLog.details).where(AuditLog.action == "user.reject")
        )
    assert details == {"reason": "unknown"}

    active = await client.post(f"/api/v1/admin/users/{anna.id}/reject", headers=headers)
    assert active.status_code == 409


@pytest.mark.db
async def test_disabling_revokes_sessions_immediately(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """A disabled user's tokens stop working at once; activation does not revive them (s. 7)."""
    anna = await user_factory(username="anna")
    annas = await bearer_for(anna)
    headers = await bearer_for(root)
    assert (await client.get("/api/v1/me", headers=annas)).status_code == 200

    disable = await client.patch(
        f"/api/v1/admin/users/{anna.id}", json={"status": "disabled"}, headers=headers
    )
    assert disable.status_code == 200
    assert disable.json()["status"] == "disabled"
    assert (await client.get("/api/v1/me", headers=annas)).status_code == 401

    enable = await client.patch(
        f"/api/v1/admin/users/{anna.id}", json={"status": "active"}, headers=headers
    )
    assert enable.json()["status"] == "active"
    assert (await client.get("/api/v1/me", headers=annas)).status_code == 401
    assert (await client.get("/api/v1/me", headers=await bearer_for(anna))).status_code == 200
    assert {"user.deactivate", "user.activate"} <= set(await actions(db_sessionmaker))


@pytest.mark.db
async def test_role_change_takes_effect_on_the_next_request(
    client: httpx.AsyncClient, root: User, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """The role is read from the database, so the same token gets the new rights (s. 6, 7)."""
    anna = await user_factory(username="anna")
    annas = await bearer_for(anna)
    assert (
        await client.post("/api/v1/teams", json={"name": "A"}, headers=annas)
    ).status_code == 403

    promote = await client.patch(
        f"/api/v1/admin/users/{anna.id}", json={"role": "team_lead"}, headers=await bearer_for(root)
    )
    assert promote.json()["role"] == "team_lead"
    assert (
        await client.post("/api/v1/teams", json={"name": "A"}, headers=annas)
    ).status_code == 201


@pytest.mark.db
async def test_status_change_of_a_pending_account_is_409(
    client: httpx.AsyncClient, root: User, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """Pending accounts are approved or rejected, not activated through PATCH."""
    newbie = await user_factory(username="newbie", status=UserStatus.pending)
    response = await client.patch(
        f"/api/v1/admin/users/{newbie.id}",
        json={"status": "active"},
        headers=await bearer_for(root),
    )
    assert (response.status_code, response.json()["code"]) == (409, "invalid_user_state")


@pytest.mark.db
@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [("PATCH", "", {"role": "user"}), ("PATCH", "", {"status": "disabled"}), ("DELETE", "", None)],
)
async def test_admin_cannot_demote_disable_or_delete_themself(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
    method: str,
    suffix: str,
    body: dict | None,
) -> None:
    """Acting on yourself is 409 last_admin even with other admins around."""
    await user_factory(username="second", role=Role.admin)
    response = await client.request(
        method, f"/api/v1/admin/users/{root.id}{suffix}", json=body, headers=await bearer_for(root)
    )
    assert (response.status_code, response.json()["code"]) == (409, "last_admin")
    assert await status_of(db_sessionmaker, root.id) == (Role.admin, UserStatus.active)


@pytest.mark.db
async def test_the_last_active_admin_is_protected(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """With two admins one may demote the other; then the remaining one is the last (s. 11)."""
    second = await user_factory(username="second", role=Role.admin)
    roots = await bearer_for(root)
    seconds = await bearer_for(second)

    demote = await client.patch(
        f"/api/v1/admin/users/{second.id}", json={"role": "user"}, headers=roots
    )
    assert demote.status_code == 200
    # `second` is no admin any more, so the admin area is gone for them.
    gone = await client.patch(
        f"/api/v1/admin/users/{root.id}", json={"role": "user"}, headers=seconds
    )
    assert gone.status_code == 404
    assert await status_of(db_sessionmaker, root.id) == (Role.admin, UserStatus.active)


@pytest.mark.db
async def test_revoke_sessions_logs_the_user_out(
    client: httpx.AsyncClient, root: User, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """Force logout everywhere: the user's tokens are rejected at once."""
    anna = await user_factory(username="anna")
    annas = await bearer_for(anna)
    response = await client.post(
        f"/api/v1/admin/users/{anna.id}/revoke-sessions", headers=await bearer_for(root)
    )
    assert response.status_code == 204
    assert (await client.get("/api/v1/me", headers=annas)).status_code == 401


@pytest.mark.db
async def test_delete_user_deletes_blobs_then_the_user(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Blobs are deleted, then the user with files and owned teams; audit keeps the count."""
    lead = await user_factory(username="lead", role=Role.team_lead)
    leads = await bearer_for(lead)
    await client.post("/api/v1/teams", json={"name": "Design"}, headers=leads)
    files = [await file_factory(lead.id), await file_factory(lead.id)]

    response = await client.delete(f"/api/v1/admin/users/{lead.id}", headers=await bearer_for(root))
    assert response.status_code == 204
    assert sorted(blob_store.deleted) == sorted(f.blob_name for f in files)
    assert await status_of(db_sessionmaker, lead.id) is None
    async with db_sessionmaker() as session, session.begin():
        teams = (await session.scalars(select(Team))).all()
        details = await session.scalar(
            select(AuditLog.details).where(AuditLog.action == "user.delete")
        )
    assert teams == []
    assert details == {"files_deleted": 2}


@pytest.mark.db
async def test_delete_user_keeps_everything_when_storage_fails(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """A storage failure is 503 storage_unavailable and the user row stays."""
    anna = await user_factory(username="anna")
    await file_factory(anna.id)
    blob_store.healthy = False
    response = await client.delete(f"/api/v1/admin/users/{anna.id}", headers=await bearer_for(root))
    assert (response.status_code, response.json()["code"]) == (503, "storage_unavailable")
    assert await status_of(db_sessionmaker, anna.id) == (Role.user, UserStatus.active)
