"""File pages and their form actions.

Tests without the ``db`` marker stop before the database: they check that the upload form is
protected (the CSRF token must be the first part of the body, Origin must match) and that pages
need a login. The ``db`` tests log in with a real session in the access cookie.
"""

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select

from app.config import Settings
from app.errors import CsrfFailed
from app.models import File, Role, ShareLink
from app.routers.file_pages import MAX_CSRF_FIELD_BYTES, _read_small
from app.services import files
from tests.conftest import (
    ActAs,
    FileFactory,
    PageLogin,
    Sessionmaker,
    UserFactory,
    count_files,
    expire_link,
    page_csrf,
    post,
    storage_outage,
    used_bytes,
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
    for response in (only_file, file_first):
        assert response.status_code == 403
        assert "CSRF validation failed." in response.text
    assert blob_store.blobs == {}


@pytest.mark.parametrize(
    ("case", "status", "message"),
    [
        ("wrong token", 403, "CSRF validation failed."),
        ("storage outage", 503, "Storage is temporarily unavailable."),
    ],
)
async def test_refused_page_upload_still_reads_the_whole_body(
    client: httpx.AsyncClient,
    act_as: ActAs,
    settings: Settings,
    blob_store: InMemoryBlobStore,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    status: int,
    message: str,
) -> None:
    """The error page is sent after the rest of the body was read, so it does not become a 502."""
    user = act_as(Role.user)
    headers, form = page_csrf(settings, user)
    token = "forged" if case == "wrong token" else form["csrf_token"]
    sent = 0

    async def body() -> AsyncIterator[bytes]:
        nonlocal sent
        head = '--b\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n'
        yield f"{head}{token}\r\n".encode()
        yield b'--b\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'
        for _ in range(20):
            sent += 1
            yield b"x" * 1000
        yield b"\r\n--b--\r\n"

    if case == "storage outage":
        monkeypatch.setattr(files, "upload", storage_outage)
    response = await client.post(
        "/files/upload",
        content=body(),
        headers={**headers, "content-type": "multipart/form-data; boundary=b"},
    )
    assert response.status_code == status
    assert message in response.text
    assert sent == 20
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


async def test_csrf_field_is_read_only_up_to_its_limit() -> None:
    """A first part much longer than a token is refused as soon as it passes the limit."""
    read: list[int] = []

    async def chunks() -> AsyncIterator[bytes]:
        for number in range(5):
            read.append(number)
            yield b"x" * 100

    with pytest.raises(CsrfFailed):
        await _read_small(chunks(), MAX_CSRF_FIELD_BYTES)
    assert len(read) == 3  # 300 bytes pass the limit of 256; the rest stays unread


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
async def test_refused_type_and_rename_show_a_message(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    page_login: PageLogin,
    file_factory: FileFactory,
    blob_store: InMemoryBlobStore,
) -> None:
    """The upload page and the rename form both refuse a name without an allowed extension."""
    user = await user_factory("anna")
    login = await page_login(user)
    refused = await upload(client, login, b"hello", "tool.exe")
    assert refused.status_code == 415
    assert "This file type is not allowed." in refused.text
    assert blob_store.blobs == {}

    file = await file_factory(user.id)
    renamed = await post(client, login, f"/files/{file.id}/rename", filename="tool.exe")
    assert renamed.status_code == 422
    assert "This file type is not allowed." in renamed.text


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
    # The "Shared with me" tab lists it, also with a sort order and a page number.
    tab = await client.get("/files?tab=shared&sort=filename&page=1", headers=member[0])
    assert tab.status_code == 200 and "plan.pdf" in tab.text
    assert (await post(client, member, f"{path}/delete")).status_code == 404
    assert (await post(client, member, f"{path}/unshare", team_id=team_id)).status_code == 404
    assert (await client.get(path, headers=member[0])).status_code == 200

    await post(client, lead, f"{path}/unshare", team_id=team_id)
    assert (await client.get(path, headers=member[0])).status_code == 404


@db
async def test_storage_outage_shows_the_error_page_and_keeps_nothing(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
    blob_store: InMemoryBlobStore,
    db_sessionmaker: Sessionmaker,
) -> None:
    """An upload shows the HTML 503 page; the list works and a download still redirects.

    The download URL is signed locally, so an outage cannot stop it (section 11).
    """
    owner = await user_factory("anna")
    login = await page_login(owner)
    file = await file_factory(owner.id, size_bytes=10)
    blob_store.healthy = False

    download = await client.get(f"/files/{file.id}/download", headers=login[0])
    uploaded = await upload(client, login)

    assert download.status_code == 302
    assert uploaded.status_code == 503
    assert uploaded.headers["content-type"].startswith("text/html")
    assert await count_files(db_sessionmaker) == 1
    assert await used_bytes(db_sessionmaker, owner.id) == 10
    assert (await client.get("/files", headers=login[0])).status_code == 200


@db
async def test_stored_names_are_escaped_on_every_page(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
) -> None:
    """A file or team name with HTML is shown as text to the owner, the team and the admin.

    The name has no ``/`` because ``sanitize_filename`` keeps only what follows the last one. The
    rename and the share also put it into the audit log, so the admin's audit page is covered.
    """
    html = "<img src=x onerror=alert(1)>"
    lead_user = await user_factory("lead", role=Role.team_lead)
    lead = await page_login(lead_user)
    admin = await page_login(await user_factory("boss", role=Role.admin))
    file = await file_factory(lead_user.id)
    path = f"/files/{file.id}"
    team_path = (await post(client, lead, "/teams", name=html)).headers["location"]
    team_id = team_path.rsplit("/", 1)[-1]
    await post(client, lead, f"{path}/rename", filename=f"{html}.pdf")
    await post(client, lead, f"{path}/share", team_id=team_id)
    await post(client, lead, f"{path}/links")

    pages = [
        (lead, "/files"),
        (lead, path),
        (lead, "/links"),
        (lead, "/teams"),
        (lead, team_path),
        (admin, "/admin/files"),
        (admin, "/admin/audit?action=file.rename"),
    ]
    for login, page_path in pages:
        page = await client.get(page_path, headers=login[0])
        assert page.status_code == 200, page_path
        assert html not in page.text, page_path
        assert "&lt;img src=x" in page.text, page_path


@db
async def test_admin_deletes_a_file_from_the_admin_list(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
) -> None:
    """The admin list has a delete button that returns to it.

    The quota and audit side of an admin delete are checked in test_files.py.
    """
    owner = await user_factory("owner")
    admin = await page_login(await user_factory("boss", role=Role.admin))
    file = await file_factory(owner.id)

    listing = await client.get("/admin/files", headers=admin[0])
    assert f"/files/{file.id}/delete" in listing.text

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
    assert "No active public links." not in reloaded.text  # listed, without its URL
    async with db_sessionmaker() as session:
        assert (await session.scalars(select(ShareLink))).one().download_count == 0


async def only_link_id(db_sessionmaker: Sessionmaker) -> int:
    """The ID of the one link in the database."""
    async with db_sessionmaker() as session:
        return (await session.scalars(select(ShareLink.id))).one()


@db
@pytest.mark.parametrize(
    ("actor", "location"),
    [
        ("owner", "/files/{file_id}"),
        ("admin", "/admin/files"),  # an admin cannot open the file page
    ],
)
async def test_who_revokes_a_link_and_where_they_land(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
    db_sessionmaker: Sessionmaker,
    actor: str,
    location: str,
) -> None:
    """The owner and an admin revoke a link and land on a page they can see."""
    owner = await user_factory("owner")
    file = await file_factory(owner.id)
    owner_login = await page_login(owner)
    await post(client, owner_login, f"/files/{file.id}/links")
    link_id = await only_link_id(db_sessionmaker)

    if actor == "owner":
        who = owner_login
    else:
        who = await page_login(await user_factory("boss", role=Role.admin))

    revoked = await post(client, who, f"/links/{link_id}/revoke")
    assert revoked.status_code == 303
    assert revoked.headers["location"] == location.format(file_id=file.id)
    async with db_sessionmaker() as session:
        assert await session.scalar(select(ShareLink.revoked_at)) is not None


@db
async def test_links_pages_filter_renew_and_return_to_the_file(
    client: httpx.AsyncClient,
    user_factory: UserFactory,
    file_factory: FileFactory,
    page_login: PageLogin,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The page filters by status and file, the form redirects or shows a message on its page.

    The rules themselves are tested through the API in test_links.py; this checks the page wiring.
    """
    owner = await user_factory("owner")
    login = await page_login(owner)
    file = await file_factory(owner.id)
    await post(client, login, f"/files/{file.id}/links")
    link_id = await only_link_id(db_sessionmaker)

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
    # A bad value sent from the file page shows the file page again, not the overview.
    bad_on_file = await post(
        client, login, f"/links/{link_id}/expiry", expires_in_hours="0", next=f"/files/{file.id}"
    )
    assert bad_on_file.status_code == 422 and f"/files/{file.id}/rename" in bad_on_file.text

    await expire_link(db_sessionmaker, link_id)
    assert "No active" in (await client.get("/links", headers=login[0])).text
    expired = await client.get("/links?status=expired", headers=login[0])
    assert "Renew" in expired.text
    await post(client, login, f"/links/{link_id}/revoke")
    revoked = await client.get(f"/links?file={file.id}&status=revoked", headers=login[0])
    assert file.filename in revoked.text
