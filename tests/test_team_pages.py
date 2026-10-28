"""Team pages and form actions.

Tests without the ``db`` marker stop before the database (login, CSRF, role check). The ``db``
tests log in with a real session in the access cookie.
"""

import httpx
import pytest

from app.models import Role
from tests.conftest import PageLogin, UserFactory, post

pytestmark = pytest.mark.anyio


# --- No database needed --------------------------------------------------------------------------


# --- Needs PostgreSQL ----------------------------------------------------------------------------


@pytest.mark.db
async def test_lead_creates_a_team_and_sees_its_page(
    client: httpx.AsyncClient, user_factory: UserFactory, page_login: PageLogin
) -> None:
    """Creating a team redirects to its page, which lists the owner as a member.

    A taken name re-renders the list with the message and status 409 (D18).
    """
    lead = await page_login(await user_factory(username="lead", role=Role.team_lead))
    created = await post(client, lead, "/teams", name="Design")
    assert created.status_code == 303
    page = await client.get(created.headers["location"], headers=lead[0])
    assert page.status_code == 200
    assert "Design" in page.text and "lead" in page.text

    listing = await client.get("/teams", headers=lead[0])
    assert "Design" in listing.text

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
