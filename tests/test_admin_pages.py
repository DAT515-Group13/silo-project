"""Admin pages and form actions.

Tests without the ``db`` marker stop at the admin check or at form validation. The ``db`` tests
log in with a real session in the access cookie.
"""

import httpx
import pytest
from sqlalchemy import select

from app.config import Settings
from app.models import ActorType, AuditLog, Outcome, Role, User, UserStatus
from tests.conftest import (
    ActAs,
    FileFactory,
    PageLogin,
    Sessionmaker,
    UserFactory,
    page_csrf,
)

pytestmark = pytest.mark.anyio


# --- No database needed --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/admin"),
        ("GET", "/admin/files"),
        ("GET", "/admin/audit"),
        ("POST", "/admin/users/2"),
        ("POST", "/admin/users/2/approve"),
        ("POST", "/admin/users/2/reject"),
        ("POST", "/admin/users/2/revoke-sessions"),
        ("POST", "/admin/users/2/delete"),
    ],
)
async def test_non_admins_get_the_404_page(
    client: httpx.AsyncClient, act_as: ActAs, method: str, path: str
) -> None:
    """The admin pages do not exist for non-admins.

    The POSTs carry no CSRF token on purpose: the admin check runs first, so a 403 cannot
    reveal that the action exists.
    """
    act_as(Role.team_lead)
    response = await client.request(method, path)
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")


async def test_delete_needs_the_confirmation_box(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings
) -> None:
    """Deleting a user is final, so the form must confirm it."""
    admin = act_as(Role.admin)
    headers, data = page_csrf(settings, admin)
    response = await client.post("/admin/users/2/delete", data=data, headers=headers)
    assert response.status_code == 422
    assert "Tick the confirmation box" in response.text


@pytest.mark.parametrize(
    ("method", "path", "fields", "message"),
    [
        # Messages are matched without quotes: the page HTML-escapes them.
        ("POST", "/admin/users/2", {"role": "boss"}, "Input should be"),
        ("POST", "/admin/users/2", {"status": "pending"}, "Status must be active or disabled."),
        ("POST", "/admin/users/2/reject", {"reason": "x" * 501}, "500 characters"),
        ("GET", "/admin/audit?outcome=bogus", {}, "A filter value is not valid."),
        ("GET", "/admin/audit?actor_id=0", {}, "A filter value is not valid."),
        ("GET", "/admin/audit?from=yesterday", {}, "is not a valid date and time."),
    ],
    ids=["unknown role", "pending status", "long reason", "bad outcome", "bad actor", "bad time"],
)
async def test_bad_form_or_filter_values_show_a_422_page(
    client: httpx.AsyncClient,
    act_as: ActAs,
    settings: Settings,
    method: str,
    path: str,
    fields: dict[str, str],
    message: str,
) -> None:
    """A bad value is refused with a readable message before the service (and the database)."""
    admin = act_as(Role.admin)
    headers, data = page_csrf(settings, admin)
    form = {**data, **fields} if method == "POST" else None  # a GET filter sends no form
    response = await client.request(method, path, data=form, headers=headers)
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("text/html")
    assert message in response.text


# --- Needs PostgreSQL ----------------------------------------------------------------------------


@pytest.fixture
async def admin_login(
    user_factory: UserFactory, page_login: PageLogin
) -> tuple[User, dict[str, str], dict[str, str]]:
    """An admin with a session: (user, headers with access and CSRF cookie, form data)."""
    root = await user_factory(username="root", role=Role.admin)
    headers, data = await page_login(root)
    return root, headers, data


async def state(sm: Sessionmaker, user_id: int) -> UserStatus | None:
    async with sm() as session, session.begin():
        return await session.scalar(select(User.status).where(User.id == user_id))


@pytest.mark.db
async def test_admin_approves_a_pending_user_from_the_page(
    client: httpx.AsyncClient,
    admin_login: tuple,
    user_factory: UserFactory,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The pending list shows the account; the approve form activates it."""
    _, headers, data = admin_login
    newbie = await user_factory(username="newbie", status=UserStatus.pending)

    page = await client.get("/admin?status=pending", headers=headers)
    assert page.status_code == 200
    assert "newbie" in page.text and "root" not in page.text.split("<tbody>")[1]

    response = await client.post(
        f"/admin/users/{newbie.id}/approve", data=data, headers=headers, follow_redirects=False
    )
    assert response.status_code == 303
    assert await state(db_sessionmaker, newbie.id) == UserStatus.active


@pytest.mark.db
async def test_admin_changes_rejects_and_logs_out_from_the_page(
    client: httpx.AsyncClient,
    admin_login: tuple,
    user_factory: UserFactory,
    page_login: PageLogin,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The role/status, reject and revoke-sessions forms work; a 409 becomes the error page.

    The rules themselves are tested through the API in test_admin_users.py; this checks the
    page wiring.
    """
    root, headers, data = admin_login
    anna = await user_factory(username="anna")
    newbie = await user_factory(username="newbie", status=UserStatus.pending)
    bob = await user_factory(username="bob")
    bobs = await page_login(bob)

    async def submit(path: str, **fields: str) -> httpx.Response:
        return await client.post(
            path, data={**data, **fields}, headers=headers, follow_redirects=False
        )

    changed = await submit(f"/admin/users/{anna.id}", role="team_lead", status="disabled")
    assert (changed.status_code, changed.headers["location"]) == (303, "/admin")
    async with db_sessionmaker() as session, session.begin():
        row = (
            await session.execute(select(User.role, User.status).where(User.id == anna.id))
        ).one()
    assert (row.role, row.status) == (Role.team_lead, UserStatus.disabled)

    rejected = await submit(f"/admin/users/{newbie.id}/reject", reason="unknown person")
    assert rejected.headers["location"] == "/admin?status=pending"
    assert await state(db_sessionmaker, newbie.id) == UserStatus.rejected

    assert (await client.get("/account", headers=bobs[0])).status_code == 200
    revoked = await submit(f"/admin/users/{bob.id}/revoke-sessions")
    assert revoked.headers["location"] == "/admin"
    assert (await client.get("/account", headers=bobs[0])).status_code == 303  # to /login

    myself = await submit(f"/admin/users/{root.id}", status="disabled")
    assert myself.status_code == 409  # last_admin, as the HTML error page
    assert myself.headers["content-type"].startswith("text/html")


@pytest.mark.db
async def test_admin_deletes_a_user_with_confirmation(
    client: httpx.AsyncClient,
    admin_login: tuple,
    user_factory: UserFactory,
    file_factory: FileFactory,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The list warns with the file count; the confirmed delete removes the user."""
    _, headers, data = admin_login
    anna = await user_factory(username="anna")
    await file_factory(anna.id)
    page = await client.get("/admin", headers=headers)
    assert "Delete with 1 file(s)" in page.text

    response = await client.post(
        f"/admin/users/{anna.id}/delete",
        data={**data, "confirm": "yes"},
        headers=headers,
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert await state(db_sessionmaker, anna.id) is None


@pytest.mark.db
@pytest.mark.parametrize(
    ("cap", "expected", "warns"),
    [
        (0, ["1.0 KiB", "no total cap"], False),
        (4096, ["1.0 KiB", "of 4.0 KiB", "(25%)"], False),
        (1280, ["of 1.2 KiB", "(80%)"], True),  # exactly 80% already warns (same as the alert)
    ],
    ids=["no cap", "25 percent", "80 percent"],
)
async def test_users_page_shows_the_total_storage(
    client: httpx.AsyncClient,
    settings: Settings,
    admin_login: tuple,
    user_factory: UserFactory,
    file_factory: FileFactory,
    cap: int,
    expected: list[str],
    warns: bool,
) -> None:
    """/admin shows one aggregate: all stored bytes, the cap and a warning near the cap."""
    _, headers, _ = admin_login
    settings.storage_total_max_bytes = cap
    anna = await user_factory(username="anna")
    await file_factory(anna.id, size_bytes=1024)
    page = await client.get("/admin", headers=headers)
    assert page.status_code == 200
    block = page.text.split('id="total-storage"')[1].split("</p>")[0]
    for text in expected:
        assert text in block
    assert ("almost full" in block) is warns


@pytest.mark.db
async def test_audit_and_files_pages_render(
    client: httpx.AsyncClient,
    admin_login: tuple,
    user_factory: UserFactory,
    file_factory: FileFactory,
    db_sessionmaker: Sessionmaker,
) -> None:
    """Both listings render for an admin; the audit filters select rows and stay in the form."""
    _, headers, _ = admin_login
    anna = await user_factory(username="anna")
    await file_factory(anna.id, filename="notes.txt")
    async with db_sessionmaker() as session, session.begin():
        for outcome in (Outcome.success, Outcome.failed):
            session.add(AuditLog(actor_type=ActorType.system, action="auth.login", outcome=outcome))

    files = await client.get("/admin/files", headers=headers)
    assert files.status_code == 200 and "notes.txt" in files.text
    audit = await client.get("/admin/audit?action=auth.login&outcome=success", headers=headers)
    assert audit.status_code == 200
    assert 'value="auth.login"' in audit.text
    assert "<td>success</td>" in audit.text and "<td>failed</td>" not in audit.text
