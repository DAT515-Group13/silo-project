"""Admin API: user management, the file list and the audit log.

Tests without the ``db`` marker stop at the admin check or at validation. The ``db`` tests go
through HTTP with real tokens.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select

from app.config import Settings
from app.errors import LastAdmin
from app.models import (
    ActorType,
    AuditLog,
    AuthSession,
    File,
    FileShare,
    Outcome,
    Role,
    ShareLink,
    Team,
    TeamMember,
    User,
    UserStatus,
)
from app.permissions import CurrentUser
from app.services import users as users_service
from app.services.audit import AuditContext
from tests.conftest import (
    ActAs,
    BearerFor,
    FileFactory,
    Sessionmaker,
    UserFactory,
    add_member,
    audit_actions,
    bearer,
    issue_session,
    make_link,
    team_with,
)
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
    """PATCH accepts status active or disabled only, and no unknown fields.

    The message is readable: no Python enum repr such as ``<UserStatus.active: 'active'>``.
    """
    act_as(Role.admin)
    response = await client.patch("/api/v1/admin/users/2", json=body)
    assert response.status_code == 422
    assert "<UserStatus" not in response.text


@pytest.mark.parametrize("name", ["action", "target_type", "target_id"])
async def test_audit_text_filters_refuse_a_nul_character(
    client: httpx.AsyncClient, act_as: ActAs, name: str
) -> None:
    """A NUL character is a 422, not a 500 from PostgreSQL; non-admins still get the 404."""
    path = f"/api/v1/admin/audit?{name}=a%00b"
    act_as(Role.admin)
    response = await client.get(path)
    assert (response.status_code, response.json()["code"]) == (422, "validation_error")

    act_as(Role.user)
    assert (await client.get(path)).status_code == 404


# --- Needs PostgreSQL ----------------------------------------------------------------------------


async def status_of(sm: Sessionmaker, user_id: int) -> tuple[Role, UserStatus] | None:
    async with sm() as session, session.begin():
        row = (
            await session.execute(select(User.role, User.status).where(User.id == user_id))
        ).first()
    return None if row is None else (row.role, row.status)


@pytest.fixture
async def root(user_factory: UserFactory) -> User:
    return await user_factory(username="root", role=Role.admin)


@pytest.mark.db
@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [
        ("POST", "/approve", None),
        ("POST", "/reject", None),
        ("POST", "/revoke-sessions", None),
        ("PATCH", "", {"role": "user"}),
        ("DELETE", "", None),
    ],
)
async def test_unknown_user_is_404_for_an_admin(
    client: httpx.AsyncClient,
    root: User,
    bearer_for: BearerFor,
    method: str,
    suffix: str,
    body: dict | None,
) -> None:
    """Every action on a user that does not exist is a plain 404."""
    response = await client.request(
        method, f"/api/v1/admin/users/999999{suffix}", json=body, headers=await bearer_for(root)
    )
    assert (response.status_code, response.json()["code"]) == (404, "not_found")


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
    """pending -> active, audited; approving again is 409 invalid_user_state."""
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
    assert "user.approve" in await audit_actions(db_sessionmaker)

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
    the links, not the tokens. "Revoke sessions" logs a user out the same way."""
    anna = await user_factory(username="anna")
    annas = await bearer_for(anna)
    headers = await bearer_for(root)
    file = await file_factory(anna.id)
    _, token = await make_link(client, annas, file.id)
    link = f"/s/{token}"
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
        await audit_actions(db_sessionmaker)
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
async def test_admin_can_demote_disable_and_delete_another_admin(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The rule protects only yourself and the last admin: other admins can go.

    A demoted admin loses the admin area (404) with the same token: the role is read from the
    database.
    """
    demoted = await user_factory(username="second", role=Role.admin)
    disabled = await user_factory(username="third", role=Role.admin)
    deleted = await user_factory(username="fourth", role=Role.admin)
    headers = await bearer_for(root)
    demoteds = await bearer_for(demoted)

    response = await client.patch(
        f"/api/v1/admin/users/{demoted.id}", json={"role": "user"}, headers=headers
    )
    assert response.status_code == 200
    response = await client.patch(
        f"/api/v1/admin/users/{disabled.id}", json={"status": "disabled"}, headers=headers
    )
    assert response.status_code == 200
    response = await client.delete(f"/api/v1/admin/users/{deleted.id}", headers=headers)
    assert response.status_code == 204
    assert await status_of(db_sessionmaker, demoted.id) == (Role.user, UserStatus.active)
    assert await status_of(db_sessionmaker, disabled.id) == (Role.admin, UserStatus.disabled)
    assert await status_of(db_sessionmaker, deleted.id) is None

    # `demoted` is no admin any more, so the admin area is gone for them.
    gone = await client.patch(
        f"/api/v1/admin/users/{root.id}", json={"role": "user"}, headers=demoteds
    )
    assert gone.status_code == 404
    assert await status_of(db_sessionmaker, root.id) == (Role.admin, UserStatus.active)


@pytest.mark.db
async def test_patch_without_a_change_writes_no_audit_entry(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Values equal to the current ones change nothing, so the log shows no false change."""
    anna = await user_factory(username="anna")
    response = await client.patch(
        f"/api/v1/admin/users/{anna.id}",
        json={"role": "user", "status": "active"},
        headers=await bearer_for(root),
    )
    assert response.status_code == 200
    assert await audit_actions(db_sessionmaker) == []


@pytest.mark.db
async def test_role_change_applies_to_the_same_token(
    client: httpx.AsyncClient,
    root: User,
    settings: Settings,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Promotion and demotion work on the next request, without a new login.

    The quota follows the role. A demoted team lead can create no new team, but keeps managing
    the team they own, because those rules look at ownership.
    """
    anna = await user_factory(username="anna")
    await user_factory(username="bob")
    annas = await bearer_for(anna)
    headers = await bearer_for(root)
    path = f"/api/v1/admin/users/{anna.id}"

    async def create_team(name: str) -> httpx.Response:
        return await client.post("/api/v1/teams", json={"name": name}, headers=annas)

    async def quota() -> int:
        return (await client.get("/api/v1/me", headers=annas)).json()["quota_bytes"]

    assert (await create_team("Before")).status_code == 403
    assert await quota() == settings.quota_user_bytes

    promote = await client.patch(path, json={"role": "team_lead"}, headers=headers)
    assert promote.status_code == 200
    created = await create_team("Design")
    assert created.status_code == 201
    assert await quota() == settings.quota_team_lead_bytes

    demote = await client.patch(path, json={"role": "user"}, headers=headers)
    assert demote.status_code == 200
    assert (await create_team("After")).status_code == 403
    assert await quota() == settings.quota_user_bytes

    team_id = created.json()["id"]
    assert await add_member(client, annas, team_id, "bob") == 204
    deleted = await client.delete(f"/api/v1/teams/{team_id}", headers=annas)
    assert deleted.status_code == 204
    assert (await audit_actions(db_sessionmaker)).count("user.role_change") == 2


@pytest.mark.db
async def test_two_admins_demoting_each_other_leave_one_admin(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Both requests run at once, and the row locks keep one active admin.

    The loser waits for the locks and gets 409 last_admin. If it starts after the winner
    committed, it is no admin any more and gets 404.
    """
    second = await user_factory(username="second", role=Role.admin)
    roots, seconds = await bearer_for(root), await bearer_for(second)

    async def demote(target: User, headers: dict[str, str]) -> httpx.Response:
        return await client.patch(
            f"/api/v1/admin/users/{target.id}", json={"role": "user"}, headers=headers
        )

    results = await asyncio.gather(demote(second, roots), demote(root, seconds))

    assert sorted(r.status_code for r in results) in ([200, 404], [200, 409])
    async with db_sessionmaker() as session, session.begin():
        admins = await session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.admin, User.status == UserStatus.active)
        )
    assert admins == 1


@pytest.mark.db
@pytest.mark.parametrize("action", ["demote", "disable", "delete"])
async def test_an_admin_demoted_meanwhile_cannot_remove_the_last_admin(
    root: User,
    user_factory: UserFactory,
    db_sessionmaker: Sessionmaker,
    blob_store: InMemoryBlobStore,
    action: str,
) -> None:
    """The same race without timing: the second request was authorized before the first ended.

    Its ``actor`` still says admin, so only the count under the row locks can refuse it. The
    last admin is protected from all three ways of losing the role.
    """
    second = await user_factory(username="second", role=Role.admin)
    ctx = AuditContext.system()

    def actor(user: User) -> CurrentUser:
        return CurrentUser(user.id, user.username, Role.admin, uuid.uuid4())

    async with db_sessionmaker() as session:
        await users_service.update_user(session, actor(root), second.id, ctx, role=Role.user)
    async with db_sessionmaker() as session:
        with pytest.raises(LastAdmin):
            if action == "delete":
                await users_service.delete_user(session, blob_store, actor(second), root.id, ctx)
            elif action == "disable":
                await users_service.update_user(
                    session, actor(second), root.id, ctx, status=UserStatus.disabled
                )
            else:
                await users_service.update_user(
                    session, actor(second), root.id, ctx, role=Role.user
                )

    assert await status_of(db_sessionmaker, root.id) == (Role.admin, UserStatus.active)


@pytest.mark.db
async def test_delete_user_removes_what_they_own_but_keeps_the_audit_trail(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Files, blobs, owned teams, sessions, links, memberships and shares go (section 5).

    That includes a file shared with someone else's team. The user's audit entries stay and keep
    the username, and ``user.delete`` records how many files went.
    """
    boss = await user_factory(username="boss", role=Role.team_lead)
    lead = await user_factory(username="lead", role=Role.team_lead)
    leads = await bearer_for(lead)
    await client.post("/api/v1/teams", json={"name": "Own"}, headers=leads)
    team_id = await team_with(client, await bearer_for(boss), "lead")
    shared = await file_factory(lead.id, team_id)
    private = await file_factory(lead.id)
    await make_link(client, leads, shared.id)

    response = await client.delete(f"/api/v1/admin/users/{lead.id}", headers=await bearer_for(root))
    assert response.status_code == 204
    assert sorted(blob_store.deleted) == sorted((shared.blob_name, private.blob_name))
    assert await status_of(db_sessionmaker, lead.id) is None

    leftovers = (
        (AuthSession, AuthSession.user_id == lead.id),
        (ShareLink, ShareLink.created_by == lead.id),
        (TeamMember, TeamMember.user_id == lead.id),
        (FileShare, FileShare.file_id == shared.id),
        (File, File.owner_id == lead.id),
        (Team, Team.owner_id == lead.id),
    )
    async with db_sessionmaker() as session, session.begin():
        counts = [
            await session.scalar(select(func.count()).select_from(table).where(condition))
            for table, condition in leftovers
        ]
        created = (
            await session.scalars(select(AuditLog).where(AuditLog.action == "link.create"))
        ).one()
        details = await session.scalar(
            select(AuditLog.details).where(AuditLog.action == "user.delete")
        )
    assert counts == [0, 0, 0, 0, 0, 0]
    assert (created.actor_id, created.actor_username) == (None, "lead")
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
    """A blob that cannot be deleted becomes an orphan; the user is deleted anyway."""
    anna = await user_factory(username="anna")
    await file_factory(anna.id)
    blob_store.healthy = False
    response = await client.delete(f"/api/v1/admin/users/{anna.id}", headers=await bearer_for(root))
    assert response.status_code == 204
    assert await status_of(db_sessionmaker, anna.id) is None
    async with db_sessionmaker() as session, session.begin():
        assert await session.scalar(select(func.count()).select_from(File)) == 0


# --- Admin file list and audit log -------------------------------------------


async def add_entries(sm: Sessionmaker, *entries: dict) -> None:
    """Insert audit rows directly, with explicit timestamps."""
    async with sm() as session, session.begin():
        for values in entries:
            session.add(AuditLog(actor_type=ActorType.system, **values))


@pytest.mark.db
async def test_admin_sees_every_file_as_metadata(
    client: httpx.AsyncClient,
    root: User,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
) -> None:
    """All users' files, newest first, without blob names; the admin owns none."""
    anna = await user_factory(username="anna")
    bob = await user_factory(username="bob")
    start = datetime(2026, 1, 1, tzinfo=UTC)
    await file_factory(anna.id, filename="a.txt", created_at=start)
    await file_factory(bob.id, filename="b.txt", created_at=start + timedelta(hours=1))

    body = (await client.get("/api/v1/admin/files", headers=await bearer_for(root))).json()
    assert body["total"] == 2
    assert [(i["filename"], i["owner"]["username"]) for i in body["items"]] == [
        ("b.txt", "bob"),
        ("a.txt", "anna"),
    ]
    assert all(i["is_owner"] is False and "blob_name" not in i for i in body["items"])


@pytest.mark.db
async def test_audit_is_newest_first_and_filterable(
    client: httpx.AsyncClient,
    root: User,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Filters on action, outcome, actor, target and time window; newest first; paginated."""
    headers = await bearer_for(root)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    await add_entries(
        db_sessionmaker,
        {"action": "team.create", "outcome": Outcome.success, "created_at": start},
        {
            "action": "auth.login",
            "outcome": Outcome.failed,
            "created_at": start + timedelta(hours=1),
        },
        {
            "action": "auth.login",
            "outcome": Outcome.success,
            "created_at": start + timedelta(hours=2),
        },
        {
            "action": "file.delete",
            "outcome": Outcome.success,
            "created_at": start,
            "actor_id": root.id,
            "target_type": "file",
            "target_id": "f1",
        },
    )

    async def query(params: str) -> dict:
        response = await client.get(f"/api/v1/admin/audit?{params}", headers=headers)
        assert response.status_code == 200, response.text
        return response.json()

    logins = await query("action=auth.login")
    assert [i["outcome"] for i in logins["items"]] == ["success", "failed"]
    assert (await query("action=auth.login&outcome=failed"))["total"] == 1

    window = await query("from=2026-01-01T00:30:00Z&to=2026-01-01T02:00:00Z&action=auth.login")
    assert [i["outcome"] for i in window["items"]] == ["failed"]

    for params in (f"actor_id={root.id}", "target_type=file", "target_id=f1"):
        assert [i["action"] for i in (await query(params))["items"]] == ["file.delete"]

    # Empty fields (as a GET form sends them) are ignored; page 2 of one entry is empty.
    paged = await query("page=2&size=1&target_type=&action=team.create")
    assert (paged["total"], paged["items"]) == (1, [])


@pytest.mark.db
async def test_audit_entries_carry_actor_and_ip(
    client: httpx.AsyncClient, root: User, bearer_for: BearerFor
) -> None:
    """Entries written by real actions carry the actor and the IP as strings."""
    headers = await bearer_for(root)
    await client.post("/api/v1/auth/logout-all", headers=headers)
    headers = await bearer_for(root)

    body = (await client.get("/api/v1/admin/audit?action=auth.logout_all", headers=headers)).json()
    entry = body["items"][0]
    assert entry["actor_type"] == "user"
    assert (entry["actor_id"], entry["actor_username"]) == (root.id, "root")
    assert entry["ip"] == "127.0.0.1"


@pytest.mark.db
async def test_session_and_team_actions_are_audited_with_their_actor(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Refresh, ending a session, logout and the team changes each leave an entry of the user."""
    lead = await user_factory(username="lead", role=Role.team_lead)
    anna = await user_factory(username="anna")
    first = await issue_session(db_sessionmaker, settings, lead)
    second = await issue_session(db_sessionmaker, settings, lead)
    third = await issue_session(db_sessionmaker, settings, lead)
    headers = bearer(first.access_token)

    refreshed = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": first.refresh_token}
    )
    assert refreshed.status_code == 200
    ended = await client.delete(f"/api/v1/auth/sessions/{second.session_id}", headers=headers)
    assert ended.status_code == 204
    logout = await client.post("/api/v1/auth/logout", headers=bearer(third.access_token))
    assert logout.status_code == 204
    team_id = await team_with(client, headers, "anna")
    removed = await client.delete(f"/api/v1/teams/{team_id}/members/{anna.id}", headers=headers)
    assert removed.status_code == 204
    assert (await client.delete(f"/api/v1/teams/{team_id}", headers=headers)).status_code == 204

    async with db_sessionmaker() as session, session.begin():
        rows = await session.execute(select(AuditLog.action, AuditLog.actor_username))
        entries = {tuple(row) for row in rows}
    expected = (
        "auth.refresh",
        "auth.session_revoke",
        "auth.logout",
        "team.member_remove",
        "team.delete",
    )
    assert {(action, "lead") for action in expected} <= entries
