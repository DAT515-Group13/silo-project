"""File API: listing, metadata, rename, download and delete (architecture.md sections 6, 8, 10).

Tests without the ``db`` marker stop before the database (token and body checks). The ``db``
tests go through HTTP with real tokens and check the permission matrix of section 6: no access
is always 404, never 403.
"""

import httpx
import pytest
from sqlalchemy import select

from app.config import Settings
from app.models import AuditLog, File, Role, User
from app.services.files import MULTIPART_MARGIN_BYTES
from tests.conftest import (
    ActAs,
    BearerFor,
    FileFactory,
    Sessionmaker,
    UserFactory,
    add_member,
    make_team,
)
from tests.fakes import InMemoryBlobStore, parse_download_url

pytestmark = pytest.mark.anyio


# --- No database needed --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_args",
    [
        {"json": {"file": "x"}},  # not multipart
        {"files": {"other": ("a.txt", b"x")}},  # the part is not named `file`
        {"files": {"file": ("", b"", "application/octet-stream")}},  # no file chosen
    ],
)
async def test_upload_with_a_bad_body_is_422(
    client: httpx.AsyncClient, act_as: ActAs, request_args: dict
) -> None:
    """A JSON body, a wrongly named part or an empty file name is a 422, not a crash."""
    act_as(Role.user)
    response = await client.post("/api/v1/files", **request_args)
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


async def test_huge_content_length_is_413_without_storing_anything(
    client: httpx.AsyncClient,
    act_as: ActAs,
    settings: Settings,
    blob_store: InMemoryBlobStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Upload step 1: a Content-Length far above the limit is refused before any blob work.

    The denied-upload audit entry cannot be written without a database; that is only logged.
    """
    settings.max_file_size_bytes = 1000

    async def must_not_run(*args: object, **kwargs: object) -> int:
        raise AssertionError("the upload reached blob storage")

    monkeypatch.setattr(blob_store, "upload_stream", must_not_run)
    act_as(Role.user)
    too_big = b"x" * (1000 + MULTIPART_MARGIN_BYTES + 1)
    response = await client.post("/api/v1/files", files={"file": ("a.bin", too_big)})
    assert response.status_code == 413
    assert response.json()["code"] == "file_too_large"
    assert blob_store.blobs == {}


async def test_sort_and_scope_are_validated(client: httpx.AsyncClient, act_as: ActAs) -> None:
    """Unknown sort keys and scopes are refused, so no column name reaches the database."""
    act_as(Role.user)
    assert (await client.get("/api/v1/files", params={"sort": "owner_id"})).status_code == 422
    assert (await client.get("/api/v1/files", params={"scope": "all"})).status_code == 422


# --- Needs PostgreSQL ----------------------------------------------------------------------------

db = pytest.mark.db


@db
async def test_permission_matrix_for_a_file(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
    blob_store: InMemoryBlobStore,
) -> None:
    """Owner sees and changes; a stranger gets 404 everywhere; an admin may only delete.

    The admin's delete gives the bytes back to the owner (not the admin) and removes the blob.
    """
    owner = await user_factory("owner")
    stranger = await user_factory("stranger")
    admin = await user_factory("boss", role=Role.admin)
    file = await file_factory(owner.id, size_bytes=10)
    blob_store.put(file.blob_name, b"0123456789")
    path = f"/api/v1/files/{file.id}"

    owner_h = await bearer_for(owner)
    assert (await client.get(path, headers=owner_h)).status_code == 200
    assert (await client.get(f"{path}/download", headers=owner_h)).status_code == 302

    for who in (stranger, admin):
        headers = await bearer_for(who)
        assert (await client.get(path, headers=headers)).status_code == 404
        assert (await client.get(f"{path}/download", headers=headers)).status_code == 404
        renamed = await client.patch(path, json={"filename": "x.txt"}, headers=headers)
        assert renamed.status_code == 404
        # Sharing is for the owner only: an admin can neither list nor change the shares.
        assert (await client.get(f"{path}/teams", headers=headers)).status_code == 404
        assert (await client.put(f"{path}/teams/1", headers=headers)).status_code == 404

    assert (await client.delete(path, headers=await bearer_for(stranger))).status_code == 404
    assert (await client.delete(path, headers=await bearer_for(admin))).status_code == 204
    async with db_sessionmaker() as session:
        assert await session.scalar(select(User.used_bytes).where(User.id == owner.id)) == 0
        actions = (await session.scalars(select(AuditLog.action))).all()
    assert blob_store.blobs == {}
    assert "file.delete" in actions


@db
async def test_delete_still_succeeds_when_the_blob_cannot_be_deleted(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The row is gone, the blob becomes an orphan for cleanup: still 204 (section 10)."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id, size_bytes=10)
    blob_store.put(file.blob_name, b"0123456789")
    blob_store.healthy = False
    response = await client.delete(f"/api/v1/files/{file.id}", headers=await bearer_for(owner))
    assert response.status_code == 204
    async with db_sessionmaker() as session:
        assert await session.scalar(select(File).where(File.id == file.id)) is None
        assert await session.scalar(select(User.used_bytes).where(User.id == owner.id)) == 0
    assert file.blob_name in blob_store.blobs  # the orphan that cleanup will remove


@db
async def test_download_redirects_to_a_read_only_url(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
    settings: Settings,
) -> None:
    """302 to the SAS URL, `no-store`, the original name; HTML is served as octet-stream."""
    owner = await user_factory("owner")
    headers = await bearer_for(owner)
    page = await file_factory(owner.id, filename="x.html", content_type="text/html")

    response = await client.get(f"/api/v1/files/{page.id}/download", headers=headers)
    assert response.status_code == 302
    assert response.headers["cache-control"] == "no-store"
    parts = parse_download_url(response.headers["location"])
    assert parts["blob"] == page.blob_name
    assert parts["filename"] == "x.html"
    assert parts["content_type"] == "application/octet-stream"
    assert parts["sp"] == "r"
    assert parts["ttl"] == str(settings.sas_url_ttl_seconds)
    async with db_sessionmaker() as session:
        actions = (await session.scalars(select(AuditLog.action))).all()
    assert actions == ["file.download"]


@db
async def test_rename_cleans_the_name_and_is_audited(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Rename is for the owner; path parts are removed from the new name; it is audited."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    response = await client.patch(
        f"/api/v1/files/{file.id}",
        json={"filename": "../../new name.pdf"},
        headers=await bearer_for(owner),
    )
    assert response.status_code == 200
    assert response.json()["filename"] == "new name.pdf"
    async with db_sessionmaker() as session:
        entry = (
            await session.scalars(select(AuditLog).where(AuditLog.action == "file.rename"))
        ).one()
    assert entry.details == {"from": "report.pdf", "to": "new name.pdf"}


@db
async def test_listing_scopes_sorting_and_pagination(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """`mine` lists own files only; sort and pages work; the total counts all rows."""
    anna = await user_factory("anna")
    bob = await user_factory("bob")
    for name, size in [("b.txt", 5), ("a.txt", 30), ("c.txt", 10)]:
        await file_factory(anna.id, filename=name, size_bytes=size)
    await file_factory(bob.id, filename="bobs.txt")
    headers = await bearer_for(anna)

    response = await client.get("/api/v1/files", params={"sort": "filename"}, headers=headers)
    body = response.json()
    assert [f["filename"] for f in body["items"]] == ["a.txt", "b.txt", "c.txt"]
    assert body["total"] == 3

    response = await client.get(
        "/api/v1/files", params={"sort": "-size_bytes", "size": 2, "page": 2}, headers=headers
    )
    body = response.json()
    assert [f["filename"] for f in body["items"]] == ["b.txt"]
    assert body["total"] == 3

    response = await client.get("/api/v1/files", params={"scope": "shared"}, headers=headers)
    assert response.json()["total"] == 0


@db
async def test_metadata_works_while_storage_is_down(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
) -> None:
    """Only upload, download and blob deletion need storage; metadata keeps working (section 11)."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    headers = await bearer_for(owner)
    blob_store.healthy = False
    assert (await client.get("/api/v1/files", headers=headers)).status_code == 200
    assert (await client.get(f"/api/v1/files/{file.id}", headers=headers)).status_code == 200
    renamed = await client.patch(
        f"/api/v1/files/{file.id}", json={"filename": "new.pdf"}, headers=headers
    )
    assert renamed.status_code == 200
    assert (
        await client.get(f"/api/v1/files/{file.id}/download", headers=headers)
    ).status_code == 503


# --- Sharing with teams (needs PostgreSQL) -------------------------------------------------------


async def team_with(client: httpx.AsyncClient, lead_headers: dict, *usernames: str) -> int:
    """The lead creates a team and adds the given usernames; returns the team ID."""
    team_id = await make_team(client, lead_headers)
    for username in usernames:
        assert await add_member(client, lead_headers, team_id, username) == 204
    return team_id


@db
async def test_member_sees_and_downloads_but_cannot_change(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """A team member can view and download a shared file, not rename or delete it (section 6)."""
    lead = await user_factory("lead", role=Role.team_lead)
    member = await user_factory("member")
    file = await file_factory(lead.id)
    lead_h, member_h = await bearer_for(lead), await bearer_for(member)
    team_id = await team_with(client, lead_h, "member")
    path = f"/api/v1/files/{file.id}"

    assert (await client.get(path, headers=member_h)).status_code == 404  # not shared yet
    shared = await client.put(f"{path}/teams/{team_id}", headers=lead_h)
    assert shared.status_code == 204

    assert (await client.get(path, headers=member_h)).json()["is_owner"] is False
    assert (await client.get(f"{path}/download", headers=member_h)).status_code == 302
    listed = await client.get("/api/v1/files", params={"scope": "shared"}, headers=member_h)
    assert [f["id"] for f in listed.json()["items"]] == [str(file.id)]
    mine = await client.get("/api/v1/files", headers=member_h)
    assert mine.json()["total"] == 0
    assert (await client.patch(path, json={"filename": "x"}, headers=member_h)).status_code == 404
    assert (await client.delete(path, headers=member_h)).status_code == 404
    assert (await client.put(f"{path}/teams/{team_id}", headers=member_h)).status_code == 404
    # Links are for the owner only: a member can neither create nor list them.
    assert (await client.post(f"{path}/links", json={}, headers=member_h)).status_code == 404
    assert (await client.get(f"{path}/links", headers=member_h)).status_code == 404


@db
async def test_shared_scope_does_not_list_own_files(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """A file shared with my own team is in `mine`, not in `shared` (that tab is for others)."""
    lead = await user_factory("lead", role=Role.team_lead)
    headers = await bearer_for(lead)
    team_id = await team_with(client, headers)
    file = await file_factory(lead.id, team_id=team_id)
    shared = await client.get("/api/v1/files", params={"scope": "shared"}, headers=headers)
    mine = await client.get("/api/v1/files", headers=headers)
    assert shared.json()["total"] == 0
    assert [f["id"] for f in mine.json()["items"]] == [str(file.id)]


@db
async def test_unshare_and_leaving_end_access(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """After unsharing, or after the member leaves the team, the member gets 404 again."""
    lead = await user_factory("lead", role=Role.team_lead)
    member = await user_factory("member")
    file = await file_factory(lead.id)
    lead_h, member_h = await bearer_for(lead), await bearer_for(member)
    team_id = await team_with(client, lead_h, "member")
    path = f"/api/v1/files/{file.id}"

    await client.put(f"{path}/teams/{team_id}", headers=lead_h)
    assert (await client.delete(f"{path}/teams/{team_id}", headers=lead_h)).status_code == 204
    assert (await client.get(path, headers=member_h)).status_code == 404

    await client.put(f"{path}/teams/{team_id}", headers=lead_h)
    assert (await client.get(path, headers=member_h)).status_code == 200
    left = await client.delete(f"/api/v1/teams/{team_id}/members/{member.id}", headers=member_h)
    assert left.status_code == 204
    assert (await client.get(path, headers=member_h)).status_code == 404


@db
async def test_sharing_is_idempotent_and_audited_once(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    db_sessionmaker: Sessionmaker,
) -> None:
    """PUT twice and DELETE twice are all 204, but each change is audited only once."""
    lead = await user_factory("lead", role=Role.team_lead)
    file = await file_factory(lead.id)
    headers = await bearer_for(lead)
    team_id = await team_with(client, headers)
    url = f"/api/v1/files/{file.id}/teams/{team_id}"

    assert (await client.put(url, headers=headers)).status_code == 204
    assert (await client.put(url, headers=headers)).status_code == 204
    teams = await client.get(f"/api/v1/files/{file.id}/teams", headers=headers)
    assert [t["name"] for t in teams.json()] == ["Design"]
    assert (await client.delete(url, headers=headers)).status_code == 204
    assert (await client.delete(url, headers=headers)).status_code == 204

    async with db_sessionmaker() as session:
        actions = (
            await session.scalars(select(AuditLog.action).where(AuditLog.action.like("file.%")))
        ).all()
    assert sorted(actions) == ["file.share", "file.unshare"]


@db
async def test_cannot_share_with_a_team_you_are_not_in(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """Sharing only works with own teams; another team and a missing team are both 404."""
    lead = await user_factory("lead", role=Role.team_lead)
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    team_id = await team_with(client, await bearer_for(lead))
    headers = await bearer_for(owner)

    for target in (team_id, 999_999):
        response = await client.put(f"/api/v1/files/{file.id}/teams/{target}", headers=headers)
        assert response.status_code == 404
    # The list of teams is for the owner only.
    other = await bearer_for(lead)
    assert (await client.get(f"/api/v1/files/{file.id}/teams", headers=other)).status_code == 404
