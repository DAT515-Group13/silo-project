"""Admin file list and audit log.

The 404 for non-admins is covered without a database in ``test_admin_users.py``.
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.models import ActorType, AuditLog, Outcome, Role
from tests.conftest import BearerFor, FileFactory, Sessionmaker, UserFactory

pytestmark = [pytest.mark.anyio, pytest.mark.db]


async def add_entries(sm: Sessionmaker, *entries: dict) -> None:
    """Insert audit rows directly, with explicit timestamps."""
    async with sm() as session, session.begin():
        for values in entries:
            session.add(AuditLog(actor_type=ActorType.system, **values))


async def test_admin_sees_every_file_as_metadata(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    file_factory: FileFactory,
) -> None:
    """All users' files, newest first, without blob names; the admin owns none (s. 6, 9.3)."""
    root = await user_factory(username="root", role=Role.admin)
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


async def test_audit_is_newest_first_and_filterable(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Filters on action, outcome and time window; newest first; paginated."""
    root = await user_factory(username="root", role=Role.admin)
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

    # Empty fields (as a GET form sends them) are ignored; page 2 of one entry is empty.
    paged = await query("page=2&size=1&target_type=&action=team.create")
    assert (paged["total"], paged["items"]) == (1, [])


async def test_audit_entries_have_the_section_5_fields(
    client: httpx.AsyncClient, user_factory: UserFactory, bearer_for: BearerFor
) -> None:
    """Entries written by real actions carry actor, target and IP as strings."""
    root = await user_factory(username="root", role=Role.admin)
    headers = await bearer_for(root)
    await client.post("/api/v1/auth/logout-all", headers=headers)
    headers = await bearer_for(root)

    body = (await client.get("/api/v1/admin/audit?action=auth.logout_all", headers=headers)).json()
    entry = body["items"][0]
    assert entry["actor_type"] == "user"
    assert (entry["actor_id"], entry["actor_username"]) == (root.id, "root")
    assert entry["ip"] == "127.0.0.1"
