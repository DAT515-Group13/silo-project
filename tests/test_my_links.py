"""Overview of all own links and changing the expiry of a link (D30).

The ``db`` tests check the rules: only the owner sees and changes links, the lifetime counts
from now and is audited, an expired link can be renewed within the limit of 10 active links,
and a revoked link stays revoked. The maximum lifetime is tested in ``test_links.py``.
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, update

from app.models import AuditLog, Role, ShareLink
from tests.conftest import (
    BearerFor,
    FileFactory,
    PageLogin,
    Sessionmaker,
    UserFactory,
    make_link,
    open_link,
    post,
)

pytestmark = pytest.mark.anyio
db = pytest.mark.db


async def expire(db_sessionmaker: Sessionmaker, link_id: int) -> None:
    """Make a link expired one minute ago, directly in the database."""
    async with db_sessionmaker() as session, session.begin():
        await session.execute(
            update(ShareLink)
            .where(ShareLink.id == link_id)
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )


@db
async def test_overview_lists_only_own_links_and_filters_by_status_and_file(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Own links only, active by default; the status and file filters narrow the list."""
    owner = await user_factory("owner")
    other = await user_factory("other")
    owner_h, other_h = await bearer_for(owner), await bearer_for(other)
    first, second = await file_factory(owner.id), await file_factory(owner.id)
    foreign = await file_factory(other.id)
    revoked_id, token = await make_link(client, owner_h, first.id)
    expired_id, _ = await make_link(client, owner_h, first.id)
    active_id, _ = await make_link(client, owner_h, second.id)
    await make_link(client, other_h, foreign.id)
    await client.delete(f"/api/v1/links/{revoked_id}", headers=owner_h)
    await expire(db_sessionmaker, expired_id)

    async def ids(query: str) -> list[int]:
        response = await client.get(f"/api/v1/links{query}", headers=owner_h)
        assert response.status_code == 200
        assert token not in response.text and "url" not in response.text
        return [item["id"] for item in response.json()["items"]]

    assert await ids("") == [active_id]
    assert await ids("?status=expired") == [expired_id]
    assert await ids("?status=revoked") == [revoked_id]
    assert await ids("?status=all") == [active_id, expired_id, revoked_id]
    assert await ids(f"?status=all&file_id={first.id}") == [expired_id, revoked_id]
    assert await ids("?status=all&page=2&size=2") == [revoked_id]
    body = (await client.get("/api/v1/links", headers=owner_h)).json()["items"][0]
    assert body["file_id"] == str(second.id) and body["filename"] == second.filename


@db
async def test_change_expiry_counts_from_now_and_audits_old_and_new(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Shorter or longer, from now; the audit entry has the old and the new time."""
    owner = await user_factory("owner")
    headers = await bearer_for(owner)
    link_id, _ = await make_link(client, headers, (await file_factory(owner.id)).id, hours=24)
    for hours in (2, 100):
        response = await client.patch(
            f"/api/v1/links/{link_id}", json={"expires_in_hours": hours}, headers=headers
        )
        assert response.status_code == 200
        expected = datetime.now(UTC) + timedelta(hours=hours)
        assert abs(datetime.fromisoformat(response.json()["expires_at"]) - expected) < timedelta(
            minutes=1
        )
    async with db_sessionmaker() as session:
        entries = (
            await session.scalars(select(AuditLog).where(AuditLog.action == "link.update"))
        ).all()
    assert len(entries) == 2
    assert {"old_expires_at", "new_expires_at"} <= set(entries[0].details)


@db
async def test_only_the_owner_changes_a_link_and_a_revoked_link_stays_revoked(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Stranger, admin, unknown ID and a revoked link all get 404; revoking stays final."""
    owner = await user_factory("owner")
    stranger = await user_factory("stranger")
    admin = await user_factory("boss", role=Role.admin)
    owner_h, stranger_h, admin_h = [await bearer_for(u) for u in (owner, stranger, admin)]
    file = await file_factory(owner.id)
    link_id, _ = await make_link(client, owner_h, file.id)
    body = {"expires_in_hours": 5}

    for headers in (stranger_h, admin_h):
        response = await client.patch(f"/api/v1/links/{link_id}", json=body, headers=headers)
        assert response.status_code == 404
    unknown = await client.patch("/api/v1/links/999999", json=body, headers=owner_h)
    assert unknown.status_code == 404

    await client.delete(f"/api/v1/links/{link_id}", headers=owner_h)
    revoked = await client.patch(f"/api/v1/links/{link_id}", json=body, headers=owner_h)
    assert revoked.status_code == 404
    async with db_sessionmaker() as session:
        assert await session.scalar(select(ShareLink.revoked_at)) is not None


@db
async def test_renewal_respects_the_limit_and_makes_the_same_url_work_again(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """With 10 active links the renewal is 409; after one revoke it succeeds and the URL works."""
    owner = await user_factory("owner")
    headers = await bearer_for(owner)
    file = await file_factory(owner.id)
    expired_id, token = await make_link(client, headers, file.id)
    await expire(db_sessionmaker, expired_id)
    active = [(await make_link(client, headers, file.id))[0] for _ in range(10)]
    url, body = f"/api/v1/links/{expired_id}", {"expires_in_hours": 1}

    refused = await client.patch(url, json=body, headers=headers)
    assert refused.status_code == 409 and refused.json()["code"] == "link_limit"
    assert (await open_link(client, token)).status_code == 404

    await client.delete(f"/api/v1/links/{active[0]}", headers=headers)
    assert (await client.patch(url, json=body, headers=headers)).status_code == 200
    assert (await open_link(client, token)).status_code == 302


@db
async def test_links_pages_filter_renew_and_return_to_the_file(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The page filters by status and file, the form redirects or shows a message.

    The rules themselves are tested through the API above; this checks the page wiring.
    """
    owner = await user_factory("owner")
    login = await page_login(owner)
    file = await file_factory(owner.id)
    await post(client, login, f"/files/{file.id}/links")
    async with db_sessionmaker() as session:
        link_id = (await session.scalars(select(ShareLink.id))).one()

    page = await client.get("/links", headers=login[0])
    assert page.status_code == 200 and f"/links/{link_id}/expiry" in page.text
    file_page = await client.get(f"/files/{file.id}", headers=login[0])
    assert f"/links?file={file.id}&status=all" in file_page.text

    changed = await post(client, login, f"/links/{link_id}/expiry", expires_in_hours="3")
    assert changed.status_code == 303 and changed.headers["location"] == "/links?updated=1"
    back = await post(
        client, login, f"/links/{link_id}/expiry", expires_in_hours="3", next=f"/files/{file.id}"
    )
    assert back.headers["location"] == f"/files/{file.id}"
    bad = await post(client, login, f"/links/{link_id}/expiry", expires_in_hours="0")
    assert bad.status_code == 422

    await expire(db_sessionmaker, link_id)
    assert "No active" in (await client.get("/links", headers=login[0])).text
    expired = await client.get("/links?status=expired", headers=login[0])
    assert "Renew" in expired.text
    await post(client, login, f"/links/{link_id}/revoke")
    revoked = await client.get(f"/links?file={file.id}&status=revoked", headers=login[0])
    assert file.filename in revoked.text
