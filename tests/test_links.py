"""Public links: creation rules, revocation and the anonymous ``/s/{token}`` endpoint.

Tests without the ``db`` marker stop before the database (validation, malformed tokens, log
redaction). The ``db`` tests go through HTTP with real tokens and check the promises of
architecture.md sections 5, 8.3 and 11: only a hash is stored, every failing link gives the same
404, and the token never reaches the audit log or the logs.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select, update

from app.config import Settings
from app.main import RedactLinkTokens
from app.models import AuditLog, Role, ShareLink, User, UserStatus
from app.schemas.links import LinkCreateIn, LinkUpdateIn
from app.security import hash_token
from tests.conftest import ActAs, BearerFor, FileFactory, Sessionmaker, UserFactory, sample
from tests.fakes import InMemoryBlobStore, parse_download_url

pytestmark = pytest.mark.anyio

PUBLIC_HEADERS = {
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    "x-robots-tag": "noindex",
}


# --- No database needed --------------------------------------------------------------------------


def test_link_hours_must_be_positive() -> None:
    """Creating defaults to 24 hours, changing has no default; both need at least 1 hour."""
    assert LinkCreateIn().expires_in_hours == 24
    with pytest.raises(ValidationError):
        LinkCreateIn(expires_in_hours=0)
    with pytest.raises(ValidationError):
        LinkUpdateIn()  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        LinkUpdateIn(expires_in_hours=0)


async def test_lifetime_above_the_maximum_is_422(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings
) -> None:
    """More than PUBLIC_LINK_MAX_HOURS is refused before the database is touched."""
    act_as(Role.user)
    response = await client.post(
        f"/api/v1/files/{uuid.uuid4()}/links",
        json={"expires_in_hours": settings.public_link_max_hours + 1},
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


# --- Needs PostgreSQL ----------------------------------------------------------------------------

db = pytest.mark.db


async def make_link(
    client: httpx.AsyncClient, headers: dict, file_id: object, hours: int = 24
) -> tuple[int, str]:
    """Create a link through the API; returns its ID and the token from the URL."""
    response = await client.post(
        f"/api/v1/files/{file_id}/links", json={"expires_in_hours": hours}, headers=headers
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["url"].startswith("http://testserver/s/")
    return body["id"], body["url"].rsplit("/", 1)[-1]


async def open_link(client: httpx.AsyncClient, token: str) -> httpx.Response:
    return await client.get(f"/s/{token}", follow_redirects=False)


def assert_same_404(response: httpx.Response) -> None:
    assert response.status_code == 404
    for name, value in PUBLIC_HEADERS.items():
        assert response.headers[name] == value


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
    """Unknown, expired, revoked and owner-disabled links are indistinguishable (section 8.3)."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    headers = await bearer_for(owner)
    _, expired = await make_link(client, headers, file.id)
    revoked_id, revoked = await make_link(client, headers, file.id)
    _, disabled = await make_link(client, headers, file.id)

    async with db_sessionmaker() as session, session.begin():
        await session.execute(
            update(ShareLink)
            .where(ShareLink.token_hash == hash_token(expired))
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    assert (await client.delete(f"/api/v1/links/{revoked_id}", headers=headers)).status_code == 204

    bodies = set()
    for token in (expired, revoked, "U" * 43):  # expired, revoked, unknown
        response = await open_link(client, token)
        assert_same_404(response)
        bodies.add(response.text)
    assert len(bodies) == 1

    # Disabling the owner stops the link; reactivating makes it work again (section 11).
    async with db_sessionmaker() as session, session.begin():
        await session.execute(
            update(User).where(User.id == owner.id).values(status=UserStatus.disabled)
        )
    assert_same_404(await open_link(client, disabled))
    async with db_sessionmaker() as session, session.begin():
        await session.execute(
            update(User).where(User.id == owner.id).values(status=UserStatus.active)
        )
    assert (await open_link(client, disabled)).status_code == 302


@db
async def test_deleting_the_file_kills_its_links(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """Links are removed with their file (cascade), so the token stops working."""
    owner = await user_factory("owner", used_bytes=10)  # the delete gives these bytes back
    file = await file_factory(owner.id)
    headers = await bearer_for(owner)
    _, token = await make_link(client, headers, file.id)
    deleted = await client.delete(f"/api/v1/files/{file.id}", headers=headers)
    assert deleted.status_code == 204
    assert_same_404(await open_link(client, token))


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
    tokens = [(await make_link(client, headers, file.id))[1] for _ in range(10)]

    refused = await client.post(f"/api/v1/files/{file.id}/links", json={}, headers=headers)
    assert refused.status_code == 409
    assert refused.json()["code"] == "link_limit"

    async with db_sessionmaker() as session, session.begin():
        await session.execute(
            update(ShareLink)
            .where(ShareLink.token_hash == hash_token(tokens[0]))
            .values(expires_at=datetime.now(UTC) - timedelta(hours=1))
        )
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
    """Section 4: link tokens are never logged or stored anywhere but as a hash."""
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
