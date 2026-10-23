"""Team pages and form actions.

Tests without the ``db`` marker stop before the database (login, CSRF, role check). The ``db``
tests log in with a real session in the access cookie.
"""

from collections.abc import Awaitable, Callable

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.middleware import cookie_names
from app.models import Role, User
from app.security import create_csrf_token
from app.services import sessions
from tests.conftest import ActAs, UserFactory, page_csrf

pytestmark = pytest.mark.anyio

PageLogin = Callable[[User], Awaitable[tuple[dict[str, str], dict[str, str]]]]


# --- No database needed --------------------------------------------------------------------------


async def test_teams_page_needs_a_login(client: httpx.AsyncClient) -> None:
    """Without a session the team list redirects to /login."""
    response = await client.get("/teams", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/teams"


async def test_plain_user_gets_403_when_creating_a_team(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings
) -> None:
    """The page answers the role check like the API: 403 role_required, as an HTML page (D19)."""
    user = act_as(Role.user)
    headers, data = page_csrf(settings, user)
    response = await client.post("/teams", data={**data, "name": "Design"}, headers=headers)
    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    assert "Your role does not allow this action." in response.text


async def test_create_team_needs_a_csrf_token(
    client: httpx.AsyncClient, act_as: ActAs, settings: Settings
) -> None:
    """Every page POST needs the CSRF token."""
    act_as(Role.team_lead)
    response = await client.post(
        "/teams", data={"name": "Design"}, headers={"Origin": settings.base_url}
    )
    assert response.status_code == 403
    assert "CSRF validation failed." in response.text


# --- Needs PostgreSQL ----------------------------------------------------------------------------


@pytest.fixture
def page_login(db_sessionmaker: async_sessionmaker[AsyncSession], settings: Settings) -> PageLogin:
    """``headers, form = await page_login(user)``: access cookie, CSRF cookie and form field."""

    async def login(user: User) -> tuple[dict[str, str], dict[str, str]]:
        async with db_sessionmaker() as session, session.begin():
            tokens = await sessions.create_session(session, settings, user)
        names = cookie_names(settings)
        csrf = create_csrf_token(settings.csrf_secret.get_secret_value(), str(tokens.session_id))
        headers = {
            "Cookie": f"{names.access}={tokens.access_token}; {names.csrf}={csrf}",
            "Origin": settings.base_url,
        }
        return headers, {"csrf_token": csrf}

    return login


async def post(
    client: httpx.AsyncClient, login: tuple[dict, dict], path: str, **fields: str
) -> httpx.Response:
    headers, data = login
    return await client.post(path, data={**data, **fields}, headers=headers, follow_redirects=False)


@pytest.mark.db
async def test_lead_creates_a_team_and_sees_its_page(
    client: httpx.AsyncClient, user_factory: UserFactory, page_login: PageLogin
) -> None:
    """Creating a team redirects to its page, which lists the owner as a member."""
    lead = await page_login(await user_factory(username="lead", role=Role.team_lead))
    created = await post(client, lead, "/teams", name="Design")
    assert created.status_code == 303
    page = await client.get(created.headers["location"], headers=lead[0])
    assert page.status_code == 200
    assert "Design" in page.text and "lead" in page.text

    listing = await client.get("/teams", headers=lead[0])
    assert "Design" in listing.text


@pytest.mark.db
async def test_duplicate_team_name_shows_the_form_again(
    client: httpx.AsyncClient, user_factory: UserFactory, page_login: PageLogin
) -> None:
    """A taken name re-renders the list with the message and status 409 (D18)."""
    lead = await page_login(await user_factory(username="lead", role=Role.team_lead))
    await post(client, lead, "/teams", name="Design")
    again = await post(client, lead, "/teams", name="Design")
    assert again.status_code == 409
    assert "You already have a team with this name." in again.text


@pytest.mark.db
async def test_add_member_shows_the_same_notice_for_any_name(
    client: httpx.AsyncClient, user_factory: UserFactory, page_login: PageLogin
) -> None:
    """Known and unknown usernames lead to the same redirect and notice."""
    lead = await page_login(await user_factory(username="lead", role=Role.team_lead))
    await user_factory(username="anna")
    team_path = (await post(client, lead, "/teams", name="Design")).headers["location"]

    known = await post(client, lead, f"{team_path}/members", username="anna")
    unknown = await post(client, lead, f"{team_path}/members", username="nobody")
    assert known.headers["location"] == unknown.headers["location"] == f"{team_path}?added=1"
    page = await client.get(known.headers["location"], headers=lead[0])
    assert "If an active account with this username exists" in page.text
    assert "anna" in page.text


@pytest.mark.db
async def test_non_member_gets_the_404_page(
    client: httpx.AsyncClient, user_factory: UserFactory, page_login: PageLogin
) -> None:
    """A team page is for members only; others get the HTML 404."""
    lead = await page_login(await user_factory(username="lead", role=Role.team_lead))
    stranger = await page_login(await user_factory(username="eve"))
    team_path = (await post(client, lead, "/teams", name="Design")).headers["location"]
    response = await client.get(team_path, headers=stranger[0])
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.db
async def test_member_leaves_and_owner_cannot(
    client: httpx.AsyncClient, user_factory: UserFactory, page_login: PageLogin
) -> None:
    """A member leaves and goes to /teams; the owner gets the 409 page."""
    lead_user = await user_factory(username="lead", role=Role.team_lead)
    lead = await page_login(lead_user)
    anna_user = await user_factory(username="anna")
    anna = await page_login(anna_user)
    team_path = (await post(client, lead, "/teams", name="Design")).headers["location"]
    await post(client, lead, f"{team_path}/members", username="anna")

    left = await post(client, anna, f"{team_path}/members/{anna_user.id}/remove")
    assert (left.status_code, left.headers["location"]) == (303, "/teams")
    owner = await post(client, lead, f"{team_path}/members/{lead_user.id}/remove")
    assert owner.status_code == 409
    assert "The team owner cannot leave the team." in owner.text
