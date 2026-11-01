"""Public links: creation rules, revocation and the anonymous ``/s/{token}`` endpoint.

Tests without the ``db`` marker stop before the database (validation, malformed tokens, log
redaction). The ``db`` tests go through HTTP with real tokens and check the promises:
only a hash is stored, every failing link gives the same 404, and the token never reaches the
audit log or the logs. The overview of all own links and changing a link's expiry are at the end
(only the owner sees and changes links, the lifetime counts from now and is audited, an expired
link can be renewed within the limit of 10 active links, a revoked link stays revoked).
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app.config import Settings
from app.main import RedactLinkTokens
from app.models import AuditLog, Role, ShareLink
from app.security import hash_token
from tests.conftest import (
    PUBLIC_HEADERS,
    ActAs,
    BearerFor,
    FileFactory,
    Sessionmaker,
    UserFactory,
    assert_same_404,
    expire_link,
    make_link,
    open_link,
    sample,
)
from tests.fakes import InMemoryBlobStore, parse_download_url

pytestmark = pytest.mark.anyio

# --- No database needed --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", f"/api/v1/files/{uuid.uuid4()}/links"), ("PATCH", "/api/v1/links/1")],
    ids=["create", "change"],
)
async def test_lifetime_above_the_maximum_is_422(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings, method: str, path: str
) -> None:
    """More than PUBLIC_LINK_MAX_HOURS is refused, when creating and when changing a link.

    The check comes before the database is touched.
    """
    act_as(Role.user)
    response = await client.request(
        method, path, json={"expires_in_hours": settings.public_link_max_hours + 1}
    )
    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "expires_in_hours"


@pytest.mark.parametrize("token", ["short", "x" * 44, "a.b" + "c" * 40, "a%20b" + "c" * 40])
async def test_malformed_token_is_a_404_with_the_privacy_headers(
    client: httpx.AsyncClient, token: str
) -> None:
    """A token that cannot exist is refused without a database lookup, like any other 404."""
    response = await client.get(f"/s/{token}")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    for name, value in PUBLIC_HEADERS.items():
        assert response.headers[name] == value


def test_access_log_hides_the_link_token() -> None:
    """Uvicorn's access log line shows /s/[redacted] instead of the secret path."""

    def record(path: str) -> logging.LogRecord:
        return logging.LogRecord(
            "uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:1", "GET", path, "1.1", 302), None,
        )  # fmt: skip

    log_filter = RedactLinkTokens()
    secret = record("/s/" + "A" * 43)
    assert log_filter.filter(secret) is True
    assert "A" * 43 not in secret.getMessage()
    assert "/s/[redacted]" in secret.getMessage()
    with_query = record("/s/" + "B" * 43 + "?x=1")
    log_filter.filter(with_query)
    assert "/s/[redacted]?x=1" in with_query.getMessage()
    other = record("/files/abc")
    log_filter.filter(other)
    assert "/files/abc" in other.getMessage()


async def test_rate_limited_public_link_keeps_the_privacy_headers(
    client: httpx.AsyncClient,
) -> None:
    """The 429 page of /s/{token} also keeps the token out of referrers and caches."""
    for _ in range(30):
        assert (await client.get("/s/short")).status_code == 404
    response = await client.get("/s/short")
    assert response.status_code == 429
    for name, value in PUBLIC_HEADERS.items():
        assert response.headers[name] == value


# --- Needs PostgreSQL ----------------------------------------------------------------------------

db = pytest.mark.db


@db
async def test_create_stores_only_the_hash_and_shows_the_url_once(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The URL is only in the creation response; the database and the listing hold no token.

    The link uses the longest allowed lifetime (one hour more is the non-db 422 test above).
    """
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    headers = await bearer_for(owner)
    hours = settings.public_link_max_hours
    response = await client.post(
        f"/api/v1/files/{file.id}/links", json={"expires_in_hours": hours}, headers=headers
    )
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    token = response.json()["url"].rsplit("/", 1)[-1]

    async with db_sessionmaker() as session:
        link = (await session.scalars(select(ShareLink))).one()
    assert link.token_hash == hash_token(token)
    assert token not in link.token_hash
    expected = datetime.now(UTC) + timedelta(hours=hours)
    assert abs(link.expires_at - expected) < timedelta(minutes=1)

    listing = await client.get(f"/api/v1/files/{file.id}/links", headers=headers)
    assert listing.status_code == 200
    assert token not in listing.text and "url" not in listing.json()[0]


@db
async def test_public_link_redirects_counts_and_audits(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
    blob_store: InMemoryBlobStore,
) -> None:
    """A valid link needs no login, redirects to a read-only URL and counts the download."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id, filename="plan.html", content_type="text/html")
    headers = await bearer_for(owner)
    link_id, token = await make_link(client, headers, file.id)
    before = sample("silo_downloads_total", kind="public_link")

    response = await open_link(client, token)
    assert response.status_code == 302
    assert sample("silo_downloads_total", kind="public_link") == before + 1
    for name, value in PUBLIC_HEADERS.items():
        assert response.headers[name] == value
    parts = parse_download_url(response.headers["location"])
    assert parts["blob"] == file.blob_name and parts["sp"] == "r"
    assert parts["filename"] == "plan.html"
    assert parts["content_type"] == "application/octet-stream"  # HTML is never rendered

    await open_link(client, token)
    listing = await client.get(f"/api/v1/files/{file.id}/links", headers=headers)
    assert listing.json()[0]["download_count"] == 2
    async with db_sessionmaker() as session:
        rows = (
            await session.scalars(select(AuditLog).where(AuditLog.action == "link.download"))
        ).all()
    assert len(rows) == 2
    assert rows[0].actor_type == "anonymous" and rows[0].target_id == str(link_id)


@db
async def test_every_failing_link_gives_the_same_404(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Unknown, expired, revoked and deleted-file links are indistinguishable.

    A file's links are removed with it (cascade). A disabled owner: see the admin tests.
    """
    owner = await user_factory("owner")
    file, gone = await file_factory(owner.id), await file_factory(owner.id)
    headers = await bearer_for(owner)
    expired_id, expired = await make_link(client, headers, file.id)
    revoked_id, revoked = await make_link(client, headers, file.id)
    _, of_deleted_file = await make_link(client, headers, gone.id)

    await expire_link(db_sessionmaker, expired_id)
    assert (await client.delete(f"/api/v1/links/{revoked_id}", headers=headers)).status_code == 204
    assert (await client.delete(f"/api/v1/files/{gone.id}", headers=headers)).status_code == 204

    bodies = set()
    for token in (expired, revoked, of_deleted_file, "U" * 43):
        response = await open_link(client, token)
        assert_same_404(response)
        bodies.add(response.text)
    assert len(bodies) == 1


@db
async def test_at_most_ten_active_links_per_file(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The 11th active link is 409 link_limit; an expired link frees a place."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    headers = await bearer_for(owner)
    link_ids = [(await make_link(client, headers, file.id))[0] for _ in range(10)]

    refused = await client.post(f"/api/v1/files/{file.id}/links", json={}, headers=headers)
    assert refused.status_code == 409
    assert refused.json()["code"] == "link_limit"

    await expire_link(db_sessionmaker, link_ids[0])
    await make_link(client, headers, file.id)  # fits again


@db
async def test_parallel_creates_at_nine_links_give_exactly_one_more(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """The file row is locked while counting, so two requests cannot both add a link."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    headers = await bearer_for(owner)
    for _ in range(9):
        await make_link(client, headers, file.id)
    url = f"/api/v1/files/{file.id}/links"
    results = await asyncio.gather(
        client.post(url, json={}, headers=headers), client.post(url, json={}, headers=headers)
    )
    assert sorted(r.status_code for r in results) == [201, 409]


@db
async def test_storage_failure_is_503_and_counts_nothing(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
    blob_store: InMemoryBlobStore,
) -> None:
    """If no download URL can be made, the visit is not counted or audited; headers stay."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    _, token = await make_link(client, await bearer_for(owner), file.id)
    blob_store.healthy = False

    response = await open_link(client, token)
    assert response.status_code == 503
    for name, value in PUBLIC_HEADERS.items():
        assert response.headers[name] == value
    async with db_sessionmaker() as session:
        assert await session.scalar(select(ShareLink.download_count)) == 0
        actions = (await session.scalars(select(AuditLog.action))).all()
    assert "link.download" not in actions


@db
async def test_who_may_manage_links(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Only the owner creates and lists; owner and admin revoke; a stranger gets 404."""
    owner = await user_factory("owner")
    stranger = await user_factory("stranger")
    admin = await user_factory("boss", role=Role.admin)
    file = await file_factory(owner.id)
    owner_h, stranger_h, admin_h = [await bearer_for(u) for u in (owner, stranger, admin)]
    link_id, token = await make_link(client, owner_h, file.id)

    base = f"/api/v1/files/{file.id}/links"
    assert (await client.post(base, json={}, headers=stranger_h)).status_code == 404
    assert (await client.post(base, json={}, headers=admin_h)).status_code == 404
    assert (await client.get(base, headers=stranger_h)).status_code == 404
    assert (await client.get(base, headers=admin_h)).status_code == 404
    assert (await client.delete(f"/api/v1/links/{link_id}", headers=stranger_h)).status_code == 404
    assert (await client.delete("/api/v1/links/999999", headers=owner_h)).status_code == 404

    assert (await client.delete(f"/api/v1/links/{link_id}", headers=admin_h)).status_code == 204
    async with db_sessionmaker() as session:
        first = await session.scalar(select(ShareLink.revoked_at))
    # Revoking again is fine and keeps the first time.
    assert (await client.delete(f"/api/v1/links/{link_id}", headers=owner_h)).status_code == 204
    async with db_sessionmaker() as session:
        assert await session.scalar(select(ShareLink.revoked_at)) == first
        actions = (await session.scalars(select(AuditLog.action))).all()
    assert actions.count("link.revoke") == 1
    assert_same_404(await open_link(client, token))


@db
async def test_the_token_never_reaches_logs_or_audit(
    client: httpx.AsyncClient,
    caplog: pytest.LogCaptureFixture,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Link tokens are never logged or stored anywhere but as a hash."""
    caplog.set_level(logging.DEBUG)
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    headers = await bearer_for(owner)
    link_id, token = await make_link(client, headers, file.id)
    await open_link(client, token)
    await client.delete(f"/api/v1/links/{link_id}", headers=headers)
    await open_link(client, token)

    # The test client logs the URLs it requests; only the server's own records count here.
    server_logs = "\n".join(
        r.getMessage() for r in caplog.records if not r.name.startswith(("httpx", "httpcore"))
    )
    assert token not in server_logs
    async with db_sessionmaker() as session:
        rows = (await session.scalars(select(AuditLog))).all()
    assert {"link.create", "link.download", "link.revoke"} <= {row.action for row in rows}
    for row in rows:
        assert token not in f"{row.target_id} {row.target_label} {row.details}"


# --- Overview of own links and changing the expiry ----------------------------


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
    await expire_link(db_sessionmaker, expired_id)

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
    await expire_link(db_sessionmaker, expired_id)
    active = [(await make_link(client, headers, file.id))[0] for _ in range(10)]
    url, body = f"/api/v1/links/{expired_id}", {"expires_in_hours": 1}

    refused = await client.patch(url, json=body, headers=headers)
    assert refused.status_code == 409 and refused.json()["code"] == "link_limit"
    assert (await open_link(client, token)).status_code == 404

    await client.delete(f"/api/v1/links/{active[0]}", headers=headers)
    assert (await client.patch(url, json=body, headers=headers)).status_code == 200
    assert (await open_link(client, token)).status_code == 302
