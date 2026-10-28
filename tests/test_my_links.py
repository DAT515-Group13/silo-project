"""Overview of all own links and changing the expiry of a link (``feat/my-links``).

The first test needs no database. The ``db`` tests check the rules: only the owner sees and
changes links, only an active link can change, the lifetime counts from now and is audited.
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select, update

from app.config import Settings
from app.models import AuditLog, Role, ShareLink
from app.schemas.links import LinkExpiryIn
from tests.conftest import (
    ActAs,
    BearerFor,
    FileFactory,
    PageLogin,
    Sessionmaker,
    UserFactory,
    post,
)
from tests.test_links import make_link

pytestmark = pytest.mark.anyio
db = pytest.mark.db


def test_expiry_hours_are_required_and_positive() -> None:
    """The new lifetime has no default and must be at least 1."""
    with pytest.raises(ValidationError):
        LinkExpiryIn()  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        LinkExpiryIn(expires_in_hours=0)


async def test_expiry_above_the_maximum_is_422(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings
) -> None:
    """More than PUBLIC_LINK_MAX_HOURS is refused before the database is touched."""
    act_as(Role.user)
    response = await client.patch(
        "/api/v1/links/1", json={"expires_in_hours": settings.public_link_max_hours + 1}
    )
    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "expires_in_hours"


@db
async def test_overview_lists_only_own_links_with_their_file(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """Links of all own files are listed (revoked too), newest first, without a token or URL."""
    owner = await user_factory("owner")
    other = await user_factory("other")
    owner_h, other_h = await bearer_for(owner), await bearer_for(other)
    first, second = await file_factory(owner.id), await file_factory(owner.id)
    foreign = await file_factory(other.id)
    old_id, token = await make_link(client, owner_h, first.id)
    new_id, _ = await make_link(client, owner_h, second.id)
    await make_link(client, other_h, foreign.id)
    await client.delete(f"/api/v1/links/{old_id}", headers=owner_h)

    response = await client.get("/api/v1/links", headers=owner_h)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert [item["id"] for item in body["items"]] == [new_id, old_id]
    assert body["items"][0]["file_id"] == str(second.id)
    assert body["items"][0]["filename"] == second.filename
    assert body["items"][1]["revoked_at"] is not None
    assert token not in response.text and "url" not in body["items"][0]
    paged = await client.get("/api/v1/links?page=2&size=1", headers=owner_h)
    assert [item["id"] for item in paged.json()["items"]] == [old_id]


@db
async def test_change_expiry_counts_from_now_and_is_audited(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The new expiry is the given hours from now (shorter or longer), and one entry is written."""
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
        actions = (await session.scalars(select(AuditLog.action))).all()
    assert actions.count("link.expiry_change") == 2


@db
async def test_only_the_owner_changes_an_active_link(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Stranger, admin and unknown ID get 404; an expired or revoked link gets 422."""
    owner = await user_factory("owner")
    stranger = await user_factory("stranger")
    admin = await user_factory("boss", role=Role.admin)
    owner_h, stranger_h, admin_h = [await bearer_for(u) for u in (owner, stranger, admin)]
    file = await file_factory(owner.id)
    link_id, _ = await make_link(client, owner_h, file.id)
    url, body = f"/api/v1/links/{link_id}", {"expires_in_hours": 5}

    assert (await client.patch(url, json=body, headers=stranger_h)).status_code == 404
    assert (await client.patch(url, json=body, headers=admin_h)).status_code == 404
    assert (
        await client.patch("/api/v1/links/999999", json=body, headers=owner_h)
    ).status_code == 404

    async with db_sessionmaker() as session, session.begin():
        await session.execute(
            update(ShareLink).values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
    expired = await client.patch(url, json=body, headers=owner_h)
    assert expired.status_code == 422
    revoked_id, _ = await make_link(client, owner_h, file.id)
    await client.delete(f"/api/v1/links/{revoked_id}", headers=owner_h)
    assert (
        await client.patch(f"/api/v1/links/{revoked_id}", json=body, headers=owner_h)
    ).status_code == 422


@db
async def test_links_page_and_expiry_form(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The page lists the links; the form redirects on success and shows a message on error."""
    owner = await user_factory("owner")
    login = await page_login(owner)
    file = await file_factory(owner.id)
    await post(client, login, f"/files/{file.id}/links")
    async with db_sessionmaker() as session:
        link_id = (await session.scalars(select(ShareLink.id))).one()

    page = await client.get("/links", headers=login[0])
    assert page.status_code == 200 and file.filename in page.text
    assert f"/links/{link_id}/expiry" in page.text

    changed = await post(client, login, f"/links/{link_id}/expiry", expires_in_hours="3")
    assert changed.status_code == 303 and changed.headers["location"] == "/links?updated=1"
    bad = await post(client, login, f"/links/{link_id}/expiry", expires_in_hours="0")
    assert bad.status_code == 422
