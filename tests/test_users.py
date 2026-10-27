"""Storage quotas: per role and the service's total cap.

The tests without the ``db`` marker check the pure parts. The ``db`` tests check the atomic
quota update against PostgreSQL, including two parallel reservations at the quota edge. The
total cap over HTTP (and its parallel edge) is tested in ``test_files_quota.py``.
"""

import pytest
from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.errors import NotFound, QuotaExceeded, StorageFull
from app.models import Role, User
from app.services.users import (
    QuotaStatus,
    get_global_remaining,
    get_quota_status,
    quota_case,
    release_quota,
    reserve_global,
    reserve_quota,
)
from tests.conftest import FakeSession, UserFactory, make_settings

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


async def test_a_disabled_total_cap_never_touches_the_database() -> None:
    """With STORAGE_TOTAL_MAX_BYTES=0 there is no extra query and no lock on any upload."""
    settings = make_settings(storage_total_max_bytes=0)
    session = FakeSession()
    assert await get_global_remaining(session, settings) is None  # type: ignore[arg-type]
    await reserve_global(session, settings, 10**12)  # type: ignore[arg-type]
    assert session.statements == []


@pytest.mark.parametrize(("used", "remaining"), [(0, 100), (60, 40), (100, 0), (150, 0)])
async def test_global_remaining_is_never_negative(used: int, remaining: int) -> None:
    """A cap lowered below the current total blocks uploads; the hint is 0, never negative."""
    settings = make_settings(storage_total_max_bytes=100)
    assert await get_global_remaining(FakeSession(used), settings) == remaining  # type: ignore[arg-type]


@pytest.mark.parametrize(("size", "fits"), [(40, True), (41, False)])
async def test_reserve_global_locks_before_it_sums(size: int, fits: bool) -> None:
    """The advisory lock is taken first, so the sum includes every upload committed before.

    60 of 100 bytes are used: 40 more fit exactly, 41 do not.
    """
    settings = make_settings(storage_total_max_bytes=100)
    session = FakeSession(used_bytes=60)
    if fits:
        await reserve_global(session, settings, size)  # type: ignore[arg-type]
    else:
        with pytest.raises(StorageFull):
            await reserve_global(session, settings, size)  # type: ignore[arg-type]
    lock, total = session.statements
    assert "pg_advisory_xact_lock" in lock
    assert "sum(users.used_bytes)" in total


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
    """The quota comes from the role in the database; an unknown user ID gives NotFound."""
    lead = await user_factory(username="lead", role=Role.team_lead, used_bytes=1200)
    async with db_sessionmaker() as session:
        status = await get_quota_status(session, SETTINGS, lead.id)
    assert status == QuotaStatus(used_bytes=1200, quota_bytes=5000)
    async with db_sessionmaker() as session:
        with pytest.raises(NotFound):
            await get_quota_status(session, SETTINGS, 4242)


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
