"""The shared database fixtures in conftest.py."""

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import Role, User, UserStatus
from app.security import verify_password
from tests.conftest import TEST_PASSWORD, UserFactory


@pytest.mark.db
@pytest.mark.anyio
async def test_first_test_creates_a_user(user_factory: UserFactory) -> None:
    """A user_factory user is saved with the defaults of the users table."""
    user = await user_factory(username="Anna")
    assert user.id == 1  # identities restart for every test
    assert (user.username, user.role, user.status) == ("anna", Role.user, UserStatus.active)
    assert user.used_bytes == 0
    assert user.created_at is not None
    assert await verify_password(user.password_hash, TEST_PASSWORD)


@pytest.mark.db
@pytest.mark.anyio
async def test_second_test_can_create_the_same_username(
    user_factory: UserFactory, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    """Tables are emptied after each test, so the same username works again without a clash."""
    await user_factory(username="anna")
    async with db_sessionmaker() as session:
        assert await session.scalar(select(func.count()).select_from(User)) == 1


@pytest.mark.db
@pytest.mark.anyio
async def test_user_factory_sets_role_and_status(user_factory: UserFactory) -> None:
    """Role and status can be chosen per user."""
    user = await user_factory(username="lead", role=Role.team_lead, status=UserStatus.pending)
    assert (user.role, user.status) == (Role.team_lead, UserStatus.pending)
