"""Admin user management.

Tests without the ``db`` marker stop at the admin check or at validation. The ``db`` tests go
through HTTP with real tokens.
"""

import httpx
import pytest
from sqlalchemy import func, select

from app.models import AuditLog, File, Role, Team, User, UserStatus
from tests.conftest import ActAs, BearerFor, FileFactory, Sessionmaker, UserFactory
from tests.fakes import InMemoryBlobStore

pytestmark = pytest.mark.anyio


def _route(method: str, path: str, body: dict | None, kind: str):
    """One table row with a readable id, e.g. ``valid: GET /api/v1/admin/users``."""
    return pytest.param(method, path, body, id=f"{kind}: {method} {path}")


# Every admin route with a valid request, then requests that would fail validation (bad body,
# bad query, bad path ID): the 404 must win over the 422.
ADMIN_ROUTES = [
    _route("GET", "/api/v1/admin/users", None, "valid"),
    _route("POST", "/api/v1/admin/users/2/approve", None, "valid"),
    _route("POST", "/api/v1/admin/users/2/reject", None, "valid"),
    _route("PATCH", "/api/v1/admin/users/2", {"role": "admin"}, "valid"),
    _route("POST", "/api/v1/admin/users/2/revoke-sessions", None, "valid"),
    _route("DELETE", "/api/v1/admin/users/2", None, "valid"),
    _route("GET", "/api/v1/admin/files", None, "valid"),
    _route("GET", "/api/v1/admin/audit", None, "valid"),
    _route("PATCH", "/api/v1/admin/users/2", {"status": "pending"}, "invalid"),
    _route("GET", "/api/v1/admin/users?status=bogus", None, "invalid"),
    _route("DELETE", "/api/v1/admin/users/0", None, "invalid"),
]


# --- No database needed --------------------------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ROUTES)
async def test_non_admins_get_404_on_every_admin_endpoint(
    client: httpx.AsyncClient, act_as: ActAs, method: str, path: str, body: dict | None
) -> None:
    """Non-admins get 404, not 403, on every admin route, and the 404 comes before any 422.

    The check is "role is not admin", so the highest non-admin role stands for all of them.
    """
    act_as(Role.team_lead)
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

    # A pending account is approved or rejected, never activated through PATCH.
    patched = await client.patch(
        f"/api/v1/admin/users/{newbie.id}", json={"status": "active"}, headers=headers
    )
    assert (patched.status_code, patched.json()["code"]) == (409, "invalid_user_state")

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
    assert (active.status_code, active.json()["code"]) == (409, "invalid_user_state")


@pytest.mark.db
async def test_disabling_revokes_sessions_immediately(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
    db_sessionmaker: Sessionmaker,
) -> None:
    """A disabled user's tokens and public links stop working at once; activation revives only
    the links, not the tokens (s. 7). "Revoke sessions" logs a user out the same way."""
    anna = await user_factory(username="anna")
    annas = await bearer_for(anna)
    headers = await bearer_for(root)
    file = await file_factory(anna.id)
    created = await client.post(f"/api/v1/files/{file.id}/links", json={}, headers=annas)
    link = f"/s/{created.json()['url'].rsplit('/', 1)[-1]}"
    assert (await client.get("/api/v1/me", headers=annas)).status_code == 200
    assert (await client.get(link)).status_code == 302

    disable = await client.patch(
        f"/api/v1/admin/users/{anna.id}", json={"status": "disabled"}, headers=headers
    )
    assert disable.status_code == 200
    assert disable.json()["status"] == "disabled"
    assert (await client.get("/api/v1/me", headers=annas)).status_code == 401
    assert (await client.get(link)).status_code == 404

    enable = await client.patch(
        f"/api/v1/admin/users/{anna.id}", json={"status": "active"}, headers=headers
    )
    assert enable.json()["status"] == "active"
    assert (await client.get("/api/v1/me", headers=annas)).status_code == 401
    assert (await client.get(link)).status_code == 302
    fresh = await bearer_for(anna)
    assert (await client.get("/api/v1/me", headers=fresh)).status_code == 200

    revoke = await client.post(f"/api/v1/admin/users/{anna.id}/revoke-sessions", headers=headers)
    assert revoke.status_code == 204
    assert (await client.get("/api/v1/me", headers=fresh)).status_code == 401
    assert {"user.deactivate", "user.activate", "user.sessions_revoke"} <= set(
        await actions(db_sessionmaker)
    )


@pytest.mark.db
@pytest.mark.parametrize(
    ("method", "body"),
    [("PATCH", {"role": "user"}), ("PATCH", {"status": "disabled"}), ("DELETE", None)],
)
async def test_admin_cannot_demote_disable_or_delete_themself(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
    method: str,
    body: dict | None,
) -> None:
    """Acting on yourself is 409 last_admin even with other admins around."""
    await user_factory(username="second", role=Role.admin)
    response = await client.request(
        method, f"/api/v1/admin/users/{root.id}", json=body, headers=await bearer_for(root)
    )
    assert (response.status_code, response.json()["code"]) == (409, "last_admin")
    assert await status_of(db_sessionmaker, root.id) == (Role.admin, UserStatus.active)


@pytest.mark.db
async def test_admin_can_demote_another_admin(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """One admin may demote another; the demoted user then loses the admin area (404).

    The same token gets the new rights at once: the role is read from the database (s. 6, 7).
    """
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
async def test_delete_user_deletes_the_user_then_the_blobs(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The user with files and owned teams is deleted, then the blobs; audit keeps the count."""
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
        files_left = await session.scalar(select(func.count()).select_from(File))
        details = await session.scalar(
            select(AuditLog.details).where(AuditLog.action == "user.delete")
        )
    assert teams == []
    assert files_left == 0
    assert details == {"files_deleted": 2}


@pytest.mark.db
async def test_delete_user_succeeds_when_storage_fails(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """A blob that cannot be deleted becomes an orphan (D24); the user is deleted anyway."""
    anna = await user_factory(username="anna")
    await file_factory(anna.id)
    blob_store.healthy = False
    response = await client.delete(f"/api/v1/admin/users/{anna.id}", headers=await bearer_for(root))
    assert response.status_code == 204
    assert await status_of(db_sessionmaker, anna.id) is None
    async with db_sessionmaker() as session, session.begin():
        assert await session.scalar(select(func.count()).select_from(File)) == 0
