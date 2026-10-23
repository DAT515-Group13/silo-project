"""Admin pages and form actions.

Tests without the ``db`` marker stop at the admin check or at form validation. The ``db`` tests
log in with a real session in the access cookie.
"""

import uuid

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.middleware import cookie_names
from app.models import Role, User, UserStatus
from app.permissions import CurrentUser
from app.routers.common import templates
from app.security import create_csrf_token
from app.services import sessions
from tests.conftest import ActAs, FileFactory, UserFactory, page_csrf

pytestmark = pytest.mark.anyio

Sessionmaker = async_sessionmaker[AsyncSession]


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


async def test_non_admin_form_post_is_404_before_any_validation(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings
) -> None:
    """Even an incomplete admin form gives a non-admin the 404, not a validation message."""
    user = act_as(Role.user)
    headers, data = page_csrf(settings, user)
    response = await client.post("/admin/users/2/delete", data=data, headers=headers)
    assert response.status_code == 404


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
    user_factory: UserFactory, db_sessionmaker: Sessionmaker, settings: Settings
) -> tuple[User, dict[str, str], dict[str, str]]:
    """An admin with a session: (user, headers with access and CSRF cookie, form data)."""
    root = await user_factory(username="root", role=Role.admin)
    async with db_sessionmaker() as session, session.begin():
        tokens = await sessions.create_session(session, settings, root)
    names = cookie_names(settings)
    csrf = create_csrf_token(settings.csrf_secret.get_secret_value(), str(tokens.session_id))
    headers = {
        "Cookie": f"{names.access}={tokens.access_token}; {names.csrf}={csrf}",
        "Origin": settings.base_url,
    }
    return root, headers, {"csrf_token": csrf}


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
async def test_admin_cannot_disable_themself_from_the_page(
    client: httpx.AsyncClient, admin_login: tuple, db_sessionmaker: Sessionmaker
) -> None:
    """Acting on yourself shows the 409 page."""
    root, headers, data = admin_login
    response = await client.post(
        f"/admin/users/{root.id}", data={**data, "status": "disabled"}, headers=headers
    )
    assert response.status_code == 409
    assert await state(db_sessionmaker, root.id) == UserStatus.active


@pytest.mark.db
async def test_audit_and_files_pages_render(
    client: httpx.AsyncClient,
    admin_login: tuple,
    user_factory: UserFactory,
    file_factory: FileFactory,
) -> None:
    """Both listings render for an admin, with filters kept in the form."""
    _, headers, _ = admin_login
    anna = await user_factory(username="anna")
    await file_factory(anna.id, filename="notes.txt")

    files = await client.get("/admin/files", headers=headers)
    assert files.status_code == 200 and "notes.txt" in files.text
    audit = await client.get("/admin/audit?action=auth.login&outcome=success", headers=headers)
    assert audit.status_code == 200
    assert 'value="auth.login"' in audit.text
