"""Admin pages and form actions.

Tests without the ``db`` marker stop at the admin check or at form validation. The ``db`` tests
log in with a real session in the access cookie.
"""

import uuid

import httpx
import pytest
from sqlalchemy import select

from app.config import Settings
from app.errors import NotFound
from app.models import ActorType, AuditLog, Outcome, Role, User, UserStatus
from app.permissions import CurrentUser
from app.routers.common import templates
from app.services import admin
from tests.conftest import ActAs, FileFactory, PageLogin, Sessionmaker, UserFactory, page_csrf

pytestmark = pytest.mark.anyio


# --- No database needed --------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/admin", "/admin/files", "/admin/audit"])
async def test_non_admins_get_the_404_page(
    client: httpx.AsyncClient, act_as: ActAs, path: str
) -> None:
    """The admin pages do not exist for non-admins."""
    act_as(Role.team_lead)
    response = await client.get(path)
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.parametrize(
    "path",
    [
        "/admin/users/2",
        "/admin/users/2/approve",
        "/admin/users/2/reject",
        "/admin/users/2/revoke-sessions",
        "/admin/users/2/delete",
    ],
)
async def test_non_admin_post_without_csrf_is_404_not_403(
    client: httpx.AsyncClient, act_as: ActAs, path: str
) -> None:
    """The admin check runs before the CSRF check, so a 403 cannot reveal the action exists."""
    act_as(Role.user)
    response = await client.post(path)
    assert response.status_code == 404


async def test_delete_needs_the_confirmation_box(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings
) -> None:
    """Deleting a user is final, so the form must confirm it."""
    admin = act_as(Role.admin)
    headers, data = page_csrf(settings, admin)
    response = await client.post("/admin/users/2/delete", data=data, headers=headers)
    assert response.status_code == 422
    assert "Tick the confirmation box" in response.text


async def test_status_form_accepts_only_active_or_disabled(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings
) -> None:
    """The page form follows the PATCH rules: no status other than active or disabled."""
    admin = act_as(Role.admin)
    headers, data = page_csrf(settings, admin)
    response = await client.post(
        "/admin/users/2", data={**data, "status": "pending"}, headers=headers
    )
    assert response.status_code == 422


async def test_audit_filter_with_a_bad_value_is_422(
    client: httpx.AsyncClient, act_as: ActAs
) -> None:
    """An unknown outcome or a non-numeric actor ID is a validation error page."""
    act_as(Role.admin)
    assert (await client.get("/admin/audit?outcome=bogus")).status_code == 422
    assert (await client.get("/admin/audit?actor_id=abc")).status_code == 422
    assert (await client.get("/admin/audit?from=yesterday")).status_code == 422


async def test_storage_totals_are_for_admins_only(settings: Settings) -> None:
    """The total is admin data: everybody else gets NotFound before any query."""
    for role in (Role.user, Role.team_lead):
        actor = CurrentUser(id=1, username="anna", role=role, session_id=uuid.uuid4())
        with pytest.raises(NotFound):
            await admin.storage_totals(None, actor, settings)  # type: ignore[arg-type]


def test_admin_link_shows_only_for_admins() -> None:
    """The navigation shows the Admin link to admins only."""

    def render(role: Role) -> str:
        user = CurrentUser(id=1, username="anna", role=role, session_id=uuid.uuid4())
        return templates.get_template("base.html").render(
            user=user, csrf_token="t", url_for=lambda *args, **kwargs: "/static/x.css"
        )

    assert 'href="/admin"' in render(Role.admin)
    assert 'href="/admin"' not in render(Role.team_lead)


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
async def test_admin_cannot_act_on_themself(
    client: httpx.AsyncClient,
    admin_login: tuple,
    user_factory: UserFactory,
    db_sessionmaker: Sessionmaker,
) -> None:
    """The page offers no controls on your own row, and a forged request is the 409 page."""
    root, headers, data = admin_login
    anna = await user_factory(username="anna")

    page = (await client.get("/admin", headers=headers)).text
    assert f"/admin/users/{anna.id}/delete" in page  # other users keep their buttons
    assert f"/admin/users/{root.id}/delete" not in page
    assert f'action="/admin/users/{root.id}"' not in page
    assert "This is your account" in page

    response = await client.post(
        f"/admin/users/{root.id}", data={**data, "status": "disabled"}, headers=headers
    )
    assert response.status_code == 409
    assert await state(db_sessionmaker, root.id) == UserStatus.active


@pytest.mark.db
@pytest.mark.parametrize(
    ("cap", "expected"),
    [
        (0, ["Total stored", "1.0 KiB", "no total cap"]),
        (4096, ["of 4.0 KiB", "(25%)"]),
        (1100, ["of 1.1 KiB", "(93%)", "almost full"]),  # 80% or more warns
    ],
)
async def test_users_page_shows_the_total_storage(
    client: httpx.AsyncClient,
    settings: Settings,
    admin_login: tuple,
    user_factory: UserFactory,
    file_factory: FileFactory,
    cap: int,
    expected: list[str],
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
    if cap < 1100:
        assert "almost full" not in block


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
