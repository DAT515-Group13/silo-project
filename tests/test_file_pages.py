"""File pages and their form actions.

Tests without the ``db`` marker stop before the database: they check that the upload form is
protected (the CSRF token must be the first part of the body, Origin must match) and that pages
need a login. The ``db`` tests log in with a real session in the access cookie.
"""

import httpx
import pytest
from sqlalchemy import select

from app.config import Settings
from app.models import File, Role, ShareLink
from tests.conftest import (
    ActAs,
    FileFactory,
    PageLogin,
    Sessionmaker,
    UserFactory,
    page_csrf,
    post,
)
from tests.fakes import InMemoryBlobStore

pytestmark = pytest.mark.anyio


# --- No database needed --------------------------------------------------------------------------


async def test_upload_needs_the_csrf_token_first(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings, blob_store: InMemoryBlobStore
) -> None:
    """A body without the token, or with the file before it, is refused before any file is read."""
    user = act_as(Role.user)
    headers, form = page_csrf(settings, user)
    file_part = ("file", ("a.txt", b"hello", "text/plain"))

    only_file = await client.post("/files/upload", files=[file_part], headers=headers)
    file_first = await client.post(
        "/files/upload",
        files=[file_part, ("csrf_token", (None, form["csrf_token"]))],
        headers=headers,
    )
    wrong_token = await client.post(
        "/files/upload", data={"csrf_token": "forged"}, files=[file_part], headers=headers
    )
    for response in (only_file, file_first, wrong_token):
        assert response.status_code == 403
        assert "CSRF validation failed." in response.text
    assert blob_store.blobs == {}


@pytest.mark.parametrize("origin", [None, "http://evil.example"])
async def test_upload_checks_the_origin(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings, origin: str | None
) -> None:
    """A missing or foreign Origin is refused, even with a valid token."""
    user = act_as(Role.user)
    headers, form = page_csrf(settings, user)
    headers.pop("Origin")
    if origin:
        headers["Origin"] = origin
    response = await client.post(
        "/files/upload",
        data=form,
        files={"file": ("a.txt", b"hello", "text/plain")},
        headers=headers,
    )
    assert response.status_code == 403


# --- Needs PostgreSQL ----------------------------------------------------------------------------

db = pytest.mark.db


async def upload(
    client: httpx.AsyncClient,
    login: tuple[dict, dict],
    data: bytes = b"hello",
    name: str = "a.txt",
) -> httpx.Response:
    headers, form = login
    return await client.post(
        "/files/upload",
        data=form,  # sent before the file, as the form does
        files={"file": (name, data, "text/plain")},
        headers=headers,
        follow_redirects=False,
    )


@db
async def test_upload_through_the_page_then_list_rename_and_delete(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    page_login: PageLogin,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The whole owner cycle through the HTML forms."""
    login = await page_login(await user_factory("anna"))
    response = await upload(client, login, b"hello", "notes.txt")
    assert response.status_code == 303
    assert response.headers["location"] == "/files?uploaded=1"
    assert len(blob_store.blobs) == 1

    listing = await client.get("/files?uploaded=1", headers=login[0])
    assert "notes.txt" in listing.text
    assert "File uploaded." in listing.text

    async with db_sessionmaker() as session:
        file = (await session.scalars(select(File))).one()
    detail = await client.get(f"/files/{file.id}", headers=login[0])
    assert detail.status_code == 200 and "Delete this file" in detail.text

    renamed = await post(client, login, f"/files/{file.id}/rename", filename="../new.txt")
    assert renamed.headers["location"] == f"/files/{file.id}?renamed=1"
    assert "new.txt" in (await client.get("/files", headers=login[0])).text

    download = await client.get(f"/files/{file.id}/download", headers=login[0])
    assert download.status_code == 302
    assert download.headers["cache-control"] == "no-store"

    # A foreign `next` is ignored (no open redirect): back to the own list.
    deleted = await post(client, login, f"/files/{file.id}/delete", next="https://evil.example")
    assert deleted.headers["location"] == "/files"
    assert blob_store.blobs == {}


@db
@pytest.mark.parametrize(
    ("data", "name", "quota", "cap", "status", "message"),
    [
        (b"too long", "a.txt", 4, 0, 413, "Storage quota exceeded."),
        (b"too long", "a.txt", 1000, 4, 507, "The service storage is full."),
        (b"", "", 4, 0, 422, "Choose a file to upload."),  # no file chosen: httpx sends no name
    ],
    ids=["own quota", "service full", "no file"],
)
async def test_refused_upload_shows_the_message_and_keeps_nothing(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    page_login: PageLogin,
    blob_store: InMemoryBlobStore,
    data: bytes,
    name: str,
    quota: int,
    cap: int,
    status: int,
    message: str,
) -> None:
    """A refused upload shows the list again with a readable message and leaves no blob."""
    settings.quota_user_bytes = quota
    settings.storage_total_max_bytes = cap
    login = await page_login(await user_factory("anna"))
    response = await upload(client, login, data, name)
    assert response.status_code == status
    assert message in response.text
    assert blob_store.blobs == {}


@db
async def test_sharing_through_the_page_and_member_view(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
) -> None:
    """The owner shares with a team; the member sees the file but no owner-only controls."""
    lead_user = await user_factory("lead", role=Role.team_lead)
    member_user = await user_factory("member")
    lead, member = await page_login(lead_user), await page_login(member_user)
    team_path = (await post(client, lead, "/teams", name="Design")).headers["location"]
    team_id = team_path.rsplit("/", 1)[-1]
    await post(client, lead, f"{team_path}/members", username="member")
    file = await file_factory(lead_user.id, filename="plan.pdf")
    path = f"/files/{file.id}"

    assert (await client.get(path, headers=member[0])).status_code == 404
    shared = await post(client, lead, f"{path}/share", team_id=team_id)
    assert shared.headers["location"] == path
    owner_page = await client.get(path, headers=lead[0])
    assert "Stop sharing" in owner_page.text

    member_page = await client.get(path, headers=member[0])
    assert member_page.status_code == 200
    assert "plan.pdf" in member_page.text
    assert "Delete this file" not in member_page.text and "Rename" not in member_page.text
    assert (await post(client, member, f"{path}/delete")).status_code == 404

    await post(client, lead, f"{path}/unshare", team_id=team_id)
    assert (await client.get(path, headers=member[0])).status_code == 404


@db
async def test_admin_deletes_a_file_from_the_admin_list(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
) -> None:
    """The admin list has a delete button that returns to it; users cannot delete others' files.

    The quota and audit side of an admin delete are checked in test_files.py.
    """
    owner = await user_factory("owner", used_bytes=10)  # the delete gives these bytes back
    stranger = await page_login(await user_factory("stranger"))
    admin = await page_login(await user_factory("boss", role=Role.admin))
    file = await file_factory(owner.id)

    listing = await client.get("/admin/files", headers=admin[0])
    assert f"/files/{file.id}/delete" in listing.text
    assert (await post(client, stranger, f"/files/{file.id}/delete")).status_code == 404

    deleted = await post(client, admin, f"/files/{file.id}/delete", next="/admin/files")
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/admin/files"


@db
async def test_link_url_is_shown_once_and_the_page_is_not_cached(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The new URL appears only in the response of the POST; a reload shows no secret."""
    owner = await user_factory("owner")
    login = await page_login(owner)
    file = await file_factory(owner.id)
    path = f"/files/{file.id}"

    created = await post(client, login, f"{path}/links", expires_in_hours="48")
    assert created.status_code == 200  # rendered, not redirected
    assert created.headers["cache-control"] == "no-store"
    assert "http://testserver/s/" in created.text
    token = created.text.split("http://testserver/s/")[1].split('"')[0]
    assert len(token) == 43

    reloaded = await client.get(path, headers=login[0])
    assert token not in reloaded.text
    assert "active" in reloaded.text  # the link is listed, without its URL
    async with db_sessionmaker() as session:
        assert (await session.scalars(select(ShareLink))).one().download_count == 0


@db
async def test_link_form_errors_show_a_message(
    client: httpx.AsyncClient,
    settings: Settings,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
) -> None:
    """A bad lifetime is 422 and the eleventh link is 409, both with a readable message."""
    owner = await user_factory("owner")
    login = await page_login(owner)
    file = await file_factory(owner.id)
    url = f"/files/{file.id}/links"

    too_long = await post(
        client, login, url, expires_in_hours=str(settings.public_link_max_hours + 1)
    )
    assert too_long.status_code == 422 and "at most" in too_long.text
    zero = await post(client, login, url, expires_in_hours="0")
    assert zero.status_code == 422
    for _ in range(10):
        assert (await post(client, login, url)).status_code == 200
    eleventh = await post(client, login, url)
    assert eleventh.status_code == 409
    assert "Too many active links for this file." in eleventh.text


@db
@pytest.mark.parametrize(
    ("actor", "status", "location"),
    [
        ("owner", 303, "/files/{file_id}"),
        ("admin", 303, "/admin/files"),  # an admin cannot open the file page
        ("stranger", 404, None),
    ],
)
async def test_who_revokes_a_link_and_where_they_land(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
    db_sessionmaker: Sessionmaker,
    actor: str,
    status: int,
    location: str | None,
) -> None:
    """The owner and an admin revoke a link, a stranger gets 404; each lands on a page they see."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    owner_login = await page_login(owner)
    await post(client, owner_login, f"/files/{file.id}/links")
    async with db_sessionmaker() as session:
        link_id = (await session.scalars(select(ShareLink.id))).one()

    if actor == "owner":
        who = owner_login
    elif actor == "admin":
        who = await page_login(await user_factory("boss", role=Role.admin))
    else:
        who = await page_login(await user_factory("stranger"))
        assert (await post(client, who, f"/files/{file.id}/links")).status_code == 404

    revoked = await post(client, who, f"/links/{link_id}/revoke")
    assert revoked.status_code == status
    if location:
        assert revoked.headers["location"] == location.format(file_id=file.id)
    async with db_sessionmaker() as session:
        revoked_at = await session.scalar(select(ShareLink.revoked_at))
    assert (revoked_at is not None) is (status == 303)
    if actor == "owner":
        # The file page lists active links only; the history is on /links.
        page = await client.get(f"/links?file={file.id}&status=revoked", headers=owner_login[0])
        assert ">revoked</span>" in page.text
