"""File API: listing, metadata, rename, download and delete.

The tests go through HTTP with real tokens and check the permission matrix: no access
is always 404, never 403. Uploads are in ``test_uploads.py``.
"""

import asyncio

import httpx
import pytest
from sqlalchemy import select

from app.config import Settings
from app.models import AuditLog, File, Role
from tests.conftest import (
    BearerFor,
    FileFactory,
    Sessionmaker,
    UserFactory,
    add_member,
    audit_actions,
    make_team,
    sample,
    team_with,
    used_bytes,
)
from tests.fakes import InMemoryBlobStore, parse_download_url

pytestmark = pytest.mark.anyio


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
    owner = await user_factory("owner", role=Role.team_lead)
    stranger = await user_factory("stranger")
    admin = await user_factory("boss", role=Role.admin)
    file = await file_factory(owner.id, size_bytes=10)
    blob_store.put(file.blob_name, b"0123456789")
    path = f"/api/v1/files/{file.id}"

    owner_h = await bearer_for(owner)
    team_id = await make_team(client, owner_h)  # a real team: the 404 below is about ownership
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
        assert (await client.put(f"{path}/teams/{team_id}", headers=headers)).status_code == 404

    assert (await client.delete(path, headers=await bearer_for(stranger))).status_code == 404
    assert (await client.delete(path, headers=await bearer_for(admin))).status_code == 204
    assert await used_bytes(db_sessionmaker, owner.id) == 0
    assert blob_store.blobs == {}
    assert "file.delete" in await audit_actions(db_sessionmaker)


@db
async def test_delete_still_succeeds_when_the_blob_cannot_be_deleted(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The row is gone, the blob becomes an orphan for cleanup: still 204."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id, size_bytes=10)
    blob_store.put(file.blob_name, b"0123456789")
    blob_store.healthy = False
    response = await client.delete(f"/api/v1/files/{file.id}", headers=await bearer_for(owner))
    assert response.status_code == 204
    async with db_sessionmaker() as session:
        assert await session.scalar(select(File).where(File.id == file.id)) is None
    assert await used_bytes(db_sessionmaker, owner.id) == 0
    assert file.blob_name in blob_store.blobs  # the orphan that cleanup will remove


@db
async def test_parallel_deletes_free_the_quota_once(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Two deletes of one file at once: the row lock lets one win, the other gets 404.

    The second file keeps the counter high, so a double release would show as a wrong number
    instead of being stopped by the ``used_bytes >= 0`` constraint.
    """
    owner = await user_factory("owner")
    await file_factory(owner.id, size_bytes=100)
    file = await file_factory(owner.id, size_bytes=30)
    blob_store.put(file.blob_name, b"x" * 30)
    headers = await bearer_for(owner)
    path = f"/api/v1/files/{file.id}"

    results = await asyncio.gather(
        client.delete(path, headers=headers), client.delete(path, headers=headers)
    )

    assert sorted(r.status_code for r in results) == [204, 404]
    assert await used_bytes(db_sessionmaker, owner.id) == 100
    assert blob_store.deleted == [file.blob_name]
    assert (await audit_actions(db_sessionmaker)).count("file.delete") == 1


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
    before = sample("silo_downloads_total", kind="user")

    response = await client.get(f"/api/v1/files/{page.id}/download", headers=headers)
    assert response.status_code == 302
    assert sample("silo_downloads_total", kind="user") == before + 1
    assert response.headers["cache-control"] == "no-store"
    parts = parse_download_url(response.headers["location"])
    assert parts["blob"] == page.blob_name
    assert parts["filename"] == "x.html"
    assert parts["content_type"] == "application/octet-stream"
    assert parts["sp"] == "r"
    assert parts["ttl"] == str(settings.sas_url_ttl_seconds)
    actions = await audit_actions(db_sessionmaker)
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
    """Metadata keeps working in an outage; a download still redirects (section 11).

    The URL is signed locally, so the failure shows in the browser, on Azure's side.
    """
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
    ).status_code == 302


@db
async def test_failed_signing_is_503_and_records_no_download(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The URL is signed first, so a signing failure is neither audited nor counted."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    headers = await bearer_for(owner)
    blob_store.signing_broken = True
    before = sample("silo_downloads_total", kind="user")

    response = await client.get(f"/api/v1/files/{file.id}/download", headers=headers)

    assert (response.status_code, response.json()["code"]) == (503, "storage_unavailable")
    assert sample("silo_downloads_total", kind="user") == before
    assert await audit_actions(db_sessionmaker) == []


# --- Sharing with teams (needs PostgreSQL) -------------------------------------------------------


@db
async def test_member_sees_and_downloads_but_cannot_change(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """A team member can view and download a shared file, not rename or delete it."""
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
    assert (
        await client.patch(path, json={"filename": "x.txt"}, headers=member_h)
    ).status_code == 404
    assert (await client.delete(path, headers=member_h)).status_code == 404
    assert (await client.put(f"{path}/teams/{team_id}", headers=member_h)).status_code == 404
    # Links are for the owner only: a member can neither create nor list them.
    assert (await client.post(f"{path}/links", json={}, headers=member_h)).status_code == 404
    assert (await client.get(f"{path}/links", headers=member_h)).status_code == 404


@db
async def test_unshare_and_leaving_end_access(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """Unsharing, leaving, being removed and a deleted team each give the member 404 again."""
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

    assert await add_member(client, lead_h, team_id, "member") == 204
    assert (await client.get(path, headers=member_h)).status_code == 200
    removed = await client.delete(f"/api/v1/teams/{team_id}/members/{member.id}", headers=lead_h)
    assert removed.status_code == 204
    assert (await client.get(path, headers=member_h)).status_code == 404

    assert await add_member(client, lead_h, team_id, "member") == 204
    assert (await client.get(path, headers=member_h)).status_code == 200
    assert (await client.delete(f"/api/v1/teams/{team_id}", headers=lead_h)).status_code == 204
    assert (await client.get(path, headers=member_h)).status_code == 404


@db
async def test_only_the_owner_can_unshare_a_file(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    bearer_for: BearerFor,
) -> None:
    """A team member, a stranger and an admin get 404, and the share stays in place."""
    lead = await user_factory("lead", role=Role.team_lead)
    member = await user_factory("member")
    stranger = await user_factory("stranger")
    admin = await user_factory("boss", role=Role.admin)
    file = await file_factory(lead.id)
    lead_h = await bearer_for(lead)
    team_id = await team_with(client, lead_h, "member")
    url = f"/api/v1/files/{file.id}/teams/{team_id}"
    assert (await client.put(url, headers=lead_h)).status_code == 204

    for who in (member, stranger, admin):
        assert (await client.delete(url, headers=await bearer_for(who))).status_code == 404

    teams = await client.get(f"/api/v1/files/{file.id}/teams", headers=lead_h)
    assert [team["id"] for team in teams.json()] == [team_id]


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
