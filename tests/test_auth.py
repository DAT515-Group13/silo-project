"""Login, lockout and the first admin (registration and logout are tested over HTTP).

Only ``lock_duration`` is pure; everything else needs PostgreSQL (marker ``db``).
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

import pytest
from argon2 import PasswordHasher
from sqlalchemy import func, select

from app.config import Settings
from app.errors import (
    AccountDisabled,
    AccountPending,
    AccountRejected,
    InvalidCredentials,
)
from app.models import AuditLog, AuthSession, Role, User, UserStatus
from app.security import decode_access_token
from app.services import auth
from app.services.users import ensure_initial_admin
from tests.conftest import (
    TEST_PASSWORD,
    Sessionmaker,
    UserFactory,
    make_settings,
    sample,
)


async def count_users(sm: Sessionmaker) -> int:
    async with sm() as db:
        return await db.scalar(select(func.count()).select_from(User)) or 0


async def get_user(sm: Sessionmaker, username: str) -> User:
    async with sm() as db:
        return await db.scalar(select(User).where(User.username == username.lower())) or fail()


def fail() -> User:
    raise AssertionError("expected a row")


async def attempt(sm: Sessionmaker, settings: Settings, username: str, password: str, **kwargs):
    """One login attempt with a fresh database session, like one request."""
    async with sm() as db:
        return await auth.login(db, settings, username, password, **kwargs)


# --- lock_duration (no database) ---------------------------------------------------------------


@pytest.mark.parametrize(("failures", "minutes"), [(10, 15), (20, 30), (500, 60)])
def test_lock_duration_doubles_and_is_capped(failures: int, minutes: int) -> None:
    """15 minutes at 10 failures, doubling at each further 10, at most 1 hour (D25)."""
    assert auth.lock_duration(make_settings(), failures) == timedelta(minutes=minutes)


# --- Login -------------------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.anyio
async def test_successful_login_issues_tokens_and_a_session(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Right credentials give a token pair, a session, a login time and an audit entry."""
    user = await user_factory(username="anna", role=Role.team_lead)
    before = sample("silo_login_attempts_total", result="success")
    tokens = await attempt(db_sessionmaker, settings, "Anna", TEST_PASSWORD, ip="203.0.113.7")
    assert sample("silo_login_attempts_total", result="success") == before + 1

    claims = decode_access_token(
        tokens.access_token,
        secrets=[settings.jwt_secret.get_secret_value()],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )
    assert claims.user_id == user.id
    assert tokens.role is Role.team_lead
    async with db_sessionmaker() as db:
        session_row = await db.get_one(AuthSession, tokens.session_id)
        actions = (await db.scalars(select(AuditLog.action))).all()
    assert str(session_row.ip) == "203.0.113.7"
    assert actions == ["auth.login"]
    assert (await get_user(db_sessionmaker, "anna")).last_login_at is not None


@pytest.mark.db
@pytest.mark.anyio
async def test_lockout_after_ten_failures(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """10 wrong passwords lock the account for 15 minutes, even for the right password.

    Attempts during the lock are audited but not counted, so spamming cannot extend the lock.
    """
    await user_factory(username="anna")
    now = datetime.now(UTC)
    invalid_before = sample("silo_login_attempts_total", result="invalid")
    locked_before = sample("silo_login_attempts_total", result="locked")
    for _ in range(10):
        with pytest.raises(InvalidCredentials):
            await attempt(db_sessionmaker, settings, "anna", "wrong-password-123", now=now)
    assert sample("silo_login_attempts_total", result="invalid") == invalid_before + 10

    user = await get_user(db_sessionmaker, "anna")
    assert user.failed_login_count == 10
    assert user.locked_until == now + timedelta(minutes=15)
    for password in ("wrong-password-123", TEST_PASSWORD) * 3:
        with pytest.raises(InvalidCredentials):
            await attempt(
                db_sessionmaker, settings, "anna", password, now=now + timedelta(minutes=5)
            )

    after = await get_user(db_sessionmaker, "anna")
    assert (after.failed_login_count, after.locked_until) == (10, user.locked_until)
    assert sample("silo_login_attempts_total", result="locked") == locked_before + 6
    async with db_sessionmaker() as db:
        actions = (await db.scalars(select(AuditLog.action))).all()
        details = (
            await db.scalars(select(AuditLog.details).where(AuditLog.outcome == "denied"))
        ).all()
    assert actions.count("auth.lockout") == 1
    assert details == [{"reason": "locked"}] * 6


@pytest.mark.db
@pytest.mark.anyio
async def test_lock_doubles_the_second_time_and_a_good_login_resets_it(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """After the lock ends 10 more failures lock for 30 minutes (counter 20), not 15.

    A good login after that lock has expired resets the counter and the lock.
    """
    await user_factory(username="anna")
    t0 = datetime.now(UTC)
    for _ in range(10):
        with pytest.raises(InvalidCredentials):
            await attempt(db_sessionmaker, settings, "anna", "wrong-password-123", now=t0)

    t1 = t0 + timedelta(minutes=16)  # the first lock is over
    for _ in range(10):
        with pytest.raises(InvalidCredentials):
            await attempt(db_sessionmaker, settings, "anna", "wrong-password-123", now=t1)

    user = await get_user(db_sessionmaker, "anna")
    assert user.failed_login_count == 20
    assert user.locked_until == t1 + timedelta(minutes=30)

    await attempt(db_sessionmaker, settings, "anna", TEST_PASSWORD, now=t1 + timedelta(minutes=31))
    user = await get_user(db_sessionmaker, "anna")
    assert (user.failed_login_count, user.locked_until) == (0, None)


@pytest.mark.db
@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status", "error"),
    [
        (UserStatus.pending, AccountPending),
        (UserStatus.rejected, AccountRejected),
        (UserStatus.disabled, AccountDisabled),
    ],
)
async def test_inactive_account_is_revealed_only_after_the_right_password(
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    status: UserStatus,
    error: type[Exception],
) -> None:
    """Right password: 403 with the account state. Wrong password: the usual 401."""
    await user_factory(username="anna", status=status)
    with pytest.raises(InvalidCredentials):
        await attempt(db_sessionmaker, settings, "anna", "wrong-password-123")
    with pytest.raises(error):
        await attempt(db_sessionmaker, settings, "anna", TEST_PASSWORD)


@pytest.mark.db
@pytest.mark.anyio
async def test_outdated_hash_is_replaced_at_login(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """A hash made with weaker parameters is rehashed after a successful login."""
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(TEST_PASSWORD)
    await user_factory(username="anna", password_hash=weak)
    await attempt(db_sessionmaker, settings, "anna", TEST_PASSWORD)
    stored = (await get_user(db_sessionmaker, "anna")).password_hash
    assert stored != weak
    assert "m=65536" in stored


# --- First admin -------------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.anyio
async def test_initial_admin_is_created_once_even_when_replicas_start_together(
    db_sessionmaker: Sessionmaker, settings: Settings
) -> None:
    """Three replicas running the check at once create exactly one active admin, no errors.

    The configured password works, and a later run changes nothing.
    """

    async def start() -> bool:
        async with db_sessionmaker() as db:
            return await ensure_initial_admin(db, settings)

    results = await asyncio.gather(start(), start(), start())
    assert sorted(results) == [False, False, True]
    assert await start() is False
    admin = await get_user(db_sessionmaker, settings.initial_admin_username)
    assert (admin.role, admin.status) == (Role.admin, UserStatus.active)
    assert await count_users(db_sessionmaker) == 1
    tokens = await attempt(
        db_sessionmaker,
        settings,
        settings.initial_admin_username,
        settings.initial_admin_password.get_secret_value(),
    )
    assert tokens.role is Role.admin


@pytest.mark.db
@pytest.mark.anyio
async def test_existing_user_with_the_admin_name_is_left_alone(
    db_sessionmaker: Sessionmaker,
    settings: Settings,
    user_factory: UserFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An existing user with the configured name is left alone (no password overwrite), loudly."""
    await user_factory(username=settings.initial_admin_username, role=Role.user)
    with caplog.at_level(logging.WARNING, logger="silo"):
        async with db_sessionmaker() as db:
            assert await ensure_initial_admin(db, settings) is False
    assert "not an admin" in caplog.text
    assert (await get_user(db_sessionmaker, settings.initial_admin_username)).role is Role.user
