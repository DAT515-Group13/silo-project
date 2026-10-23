"""Storage quotas.

The tests without the ``db`` marker check the pure parts. The ``db`` tests check the atomic
quota update against PostgreSQL, including two parallel reservations at the quota edge.
"""

import asyncio

import pytest
from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.errors import NotFound, QuotaExceeded
from app.models import Role, User
from app.services.users import (
    QuotaStatus,
    get_quota_status,
    quota_case,
    release_quota,
    reserve_quota,
)
from tests.conftest import UserFactory, make_settings

pytestmark = pytest.mark.anyio

# Small quotas, so the edges are easy to hit.
SETTINGS = make_settings(quota_user_bytes=1000, quota_team_lead_bytes=5000, quota_admin_bytes=9000)


# --- No database needed --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("used", "quota", "remaining", "can_upload"),
    [(0, 1000, 1000, True), (999, 1000, 1, True), (1000, 1000, 0, False), (3000, 1000, 0, False)],
)
def test_quota_status_remaining(used: int, quota: int, remaining: int, can_upload: bool) -> None:
    """Remaining space is never negative; a role lowered below usage blocks uploads (s. 11)."""
    status = QuotaStatus(used_bytes=used, quota_bytes=quota)
    assert status.remaining == remaining
    assert status.can_upload is can_upload


def test_quota_case_covers_every_role() -> None:
    """The SQL quota expression has one branch per role, with the configured values (s. 6)."""
    sql = str(
        quota_case(SETTINGS).compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    for role in Role:
        assert f"'{role.value}'" in sql
        assert str(SETTINGS.quota_for_role(role)) in sql


async def test_negative_sizes_are_refused() -> None:
    """A negative size is a programming error and never reaches the database."""
    with pytest.raises(ValueError):
        await reserve_quota(None, SETTINGS, 1, -1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        await release_quota(None, 1, -1)  # type: ignore[arg-type]


# --- Needs PostgreSQL ----------------------------------------------------------------------------


async def used_bytes(db_sessionmaker: async_sessionmaker[AsyncSession], user_id: int) -> int:
    async with db_sessionmaker() as session, session.begin():
        return await session.scalar(select(User.used_bytes).where(User.id == user_id))


async def reserve(db_sessionmaker: async_sessionmaker[AsyncSession], user_id: int, size: int):
    """Reserve in a transaction of its own and commit, like the upload service will."""
    async with db_sessionmaker() as session, session.begin():
        return await reserve_quota(session, SETTINGS, user_id, size)


@pytest.mark.db
async def test_get_quota_status_uses_the_role_quota(
    db_sessionmaker: async_sessionmaker[AsyncSession], user_factory: UserFactory
) -> None:
    """The quota comes from the role in the database."""
    lead = await user_factory(username="lead", role=Role.team_lead, used_bytes=1200)
    async with db_sessionmaker() as session:
        status = await get_quota_status(session, SETTINGS, lead.id)
    assert status == QuotaStatus(used_bytes=1200, quota_bytes=5000)


@pytest.mark.db
async def test_get_quota_status_of_an_unknown_user_is_not_found(
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """An unknown user ID gives NotFound."""
    async with db_sessionmaker() as session:
        with pytest.raises(NotFound):
            await get_quota_status(session, SETTINGS, 4242)


@pytest.mark.db
async def test_reserve_up_to_the_exact_quota(
    db_sessionmaker: async_sessionmaker[AsyncSession], user_factory: UserFactory
) -> None:
    """Usage may reach the quota exactly; the new value is returned."""
    user = await user_factory()
    assert await reserve(db_sessionmaker, user.id, 400) == 400
    assert await reserve(db_sessionmaker, user.id, 600) == 1000
    assert await used_bytes(db_sessionmaker, user.id) == 1000


@pytest.mark.db
async def test_one_byte_over_the_quota_changes_nothing(
    db_sessionmaker: async_sessionmaker[AsyncSession], user_factory: UserFactory
) -> None:
    """A reservation that does not fit raises QuotaExceeded and leaves usage unchanged."""
    user = await user_factory(used_bytes=500)
    with pytest.raises(QuotaExceeded):
        await reserve(db_sessionmaker, user.id, 501)
    assert await used_bytes(db_sessionmaker, user.id) == 500


@pytest.mark.db
async def test_parallel_reservations_at_the_edge_never_exceed_the_quota(
    db_sessionmaker: async_sessionmaker[AsyncSession], user_factory: UserFactory
) -> None:
    """Two parallel uploads that each fit alone but not together: exactly one wins (s. 10, 16).

    Each reservation runs on its own connection, as two app requests would.
    """
    user = await user_factory()
    results = await asyncio.gather(
        reserve(db_sessionmaker, user.id, 600),
        reserve(db_sessionmaker, user.id, 600),
        return_exceptions=True,
    )
    assert sum(isinstance(result, QuotaExceeded) for result in results) == 1
    assert sorted(r for r in results if isinstance(r, int)) == [600]
    assert await used_bytes(db_sessionmaker, user.id) == 600


@pytest.mark.db
async def test_lowered_role_blocks_new_reservations(
    db_sessionmaker: async_sessionmaker[AsyncSession], user_factory: UserFactory
) -> None:
    """A team_lead demoted below their usage keeps the files but cannot upload."""
    lead = await user_factory(username="lead", role=Role.team_lead, used_bytes=3000)
    async with db_sessionmaker() as session, session.begin():
        await session.execute(update(User).where(User.id == lead.id).values(role=Role.user))
    with pytest.raises(QuotaExceeded):
        await reserve(db_sessionmaker, lead.id, 1)
    assert await used_bytes(db_sessionmaker, lead.id) == 3000


@pytest.mark.db
async def test_release_quota_gives_the_space_back(
    db_sessionmaker: async_sessionmaker[AsyncSession], user_factory: UserFactory
) -> None:
    """Deleting a file returns its bytes to the quota."""
    user = await user_factory(used_bytes=800)
    async with db_sessionmaker() as session, session.begin():
        await release_quota(session, user.id, 300)
    assert await used_bytes(db_sessionmaker, user.id) == 500
    assert await reserve(db_sessionmaker, user.id, 500) == 1000


@pytest.mark.db
async def test_reservation_is_rolled_back_with_the_caller(
    db_sessionmaker: async_sessionmaker[AsyncSession], user_factory: UserFactory
) -> None:
    """reserve_quota never commits: if the upload transaction fails, usage is unchanged."""
    user = await user_factory()
    with pytest.raises(RuntimeError):
        async with db_sessionmaker() as session, session.begin():
            await reserve_quota(session, SETTINGS, user.id, 700)
            raise RuntimeError("files row insert failed")
    assert await used_bytes(db_sessionmaker, user.id) == 0
