"""Registration, login, lockout, logout and the first admin.

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
    ValidationFailed,
)
from app.models import AuditLog, AuthSession, Role, User, UserStatus
from app.permissions import CurrentUser
from app.security import decode_access_token
from app.services import auth, sessions
from app.services.audit import AuditContext
from app.services.users import ensure_initial_admin
from tests.conftest import GOOD_PASSWORD, TEST_PASSWORD, Sessionmaker, UserFactory, make_settings


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


@pytest.mark.parametrize(
    ("failures", "minutes"), [(5, 15), (10, 30), (15, 60), (20, 120), (40, 1440), (500, 1440)]
)
def test_lock_duration_doubles_and_is_capped(failures: int, minutes: int) -> None:
    """15 minutes at 5 failures, doubling at each further 5, at most 24 hours."""
    assert auth.lock_duration(make_settings(), failures) == timedelta(minutes=minutes)


# --- Registration ------------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.anyio
async def test_open_registration_creates_an_active_user(db_sessionmaker: Sessionmaker) -> None:
    """In `open` mode the account is active at once and the password is stored hashed."""
    settings = make_settings(registration_mode="open")
    async with db_sessionmaker() as db:
        user = await auth.register(db, settings, "anna", GOOD_PASSWORD)
    assert user is not None
    assert (user.username, user.status, user.role) == ("anna", UserStatus.active, Role.user)
    assert user.password_hash.startswith("$argon2id$")
    assert GOOD_PASSWORD not in user.password_hash


@pytest.mark.db
@pytest.mark.anyio
async def test_approval_registration_is_pending_and_hides_taken_names(
    db_sessionmaker: Sessionmaker, user_factory: UserFactory
) -> None:
    """In `approval` mode a new and a taken username get the same result: None (no enumeration)."""
    settings = make_settings(registration_mode="approval")
    await user_factory(username="taken")
    async with db_sessionmaker() as db:
        assert await auth.register(db, settings, "newbie", GOOD_PASSWORD) is None
    async with db_sessionmaker() as db:
        assert await auth.register(db, settings, "taken", GOOD_PASSWORD) is None
    assert (await get_user(db_sessionmaker, "newbie")).status is UserStatus.pending
    assert await count_users(db_sessionmaker) == 2
    # The existing account was not touched.
    assert (await get_user(db_sessionmaker, "taken")).status is UserStatus.active
    async with db_sessionmaker() as db:
        reasons = (
            await db.scalars(select(AuditLog.details).where(AuditLog.outcome == "denied"))
        ).all()
    assert reasons == [{"reason": "username_taken"}]


@pytest.mark.db
@pytest.mark.anyio
async def test_registration_enforces_the_password_policy(db_sessionmaker: Sessionmaker) -> None:
    """Too short passwords and passwords equal to the username are rejected, nothing is stored."""
    settings = make_settings(registration_mode="open")
    for password in ("short", "longusername123"):
        async with db_sessionmaker() as db:
            with pytest.raises(ValidationFailed):
                await auth.register(db, settings, "longusername123", password)
    assert await count_users(db_sessionmaker) == 0


# --- Login -------------------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.anyio
async def test_successful_login_issues_tokens_and_a_session(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Right credentials give a token pair, a session, a login time and an audit entry."""
    user = await user_factory(username="anna", role=Role.team_lead)
    tokens = await attempt(db_sessionmaker, settings, "Anna", TEST_PASSWORD, ip="203.0.113.7")

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
async def test_lockout_after_five_failures(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """5 wrong passwords lock the account for 15 minutes, even for the right password."""
    await user_factory(username="anna")
    now = datetime.now(UTC)
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            await attempt(db_sessionmaker, settings, "anna", "wrong-password-123", now=now)

    user = await get_user(db_sessionmaker, "anna")
    assert user.failed_login_count == 5
    assert user.locked_until == now + timedelta(minutes=15)
    with pytest.raises(InvalidCredentials):
        await attempt(
            db_sessionmaker, settings, "anna", TEST_PASSWORD, now=now + timedelta(minutes=1)
        )
    async with db_sessionmaker() as db:
        actions = (await db.scalars(select(AuditLog.action))).all()
    assert actions.count("auth.lockout") == 1


@pytest.mark.db
@pytest.mark.anyio
async def test_attempts_during_a_lock_are_not_counted(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Spamming a locked account changes neither the counter nor the lock (no lock extension)."""
    await user_factory(username="anna")
    now = datetime.now(UTC)
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            await attempt(db_sessionmaker, settings, "anna", "wrong-password-123", now=now)
    locked = await get_user(db_sessionmaker, "anna")

    for password in ("wrong-password-123", TEST_PASSWORD) * 3:
        with pytest.raises(InvalidCredentials):
            await attempt(
                db_sessionmaker, settings, "anna", password, now=now + timedelta(minutes=5)
            )

    after = await get_user(db_sessionmaker, "anna")
    assert after.failed_login_count == locked.failed_login_count == 5
    assert after.locked_until == locked.locked_until
    # Not counted, but each attempt is in the audit log.
    async with db_sessionmaker() as db:
        details = (
            await db.scalars(select(AuditLog.details).where(AuditLog.outcome == "denied"))
        ).all()
    assert details == [{"reason": "locked"}] * 6


@pytest.mark.db
@pytest.mark.anyio
async def test_second_lock_is_twice_as_long_and_the_counter_survives_expiry(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """After the lock ends 5 more failures lock for 30 minutes (counter 10), not 15."""
    await user_factory(username="anna")
    t0 = datetime.now(UTC)
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            await attempt(db_sessionmaker, settings, "anna", "wrong-password-123", now=t0)

    t1 = t0 + timedelta(minutes=16)  # the first lock is over
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            await attempt(db_sessionmaker, settings, "anna", "wrong-password-123", now=t1)

    user = await get_user(db_sessionmaker, "anna")
    assert user.failed_login_count == 10
    assert user.locked_until == t1 + timedelta(minutes=30)


@pytest.mark.db
@pytest.mark.anyio
async def test_successful_login_resets_counter_and_lock(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """A good login after an expired lock resets failed_login_count and locked_until."""
    await user_factory(username="anna")
    t0 = datetime.now(UTC)
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            await attempt(db_sessionmaker, settings, "anna", "wrong-password-123", now=t0)
    await attempt(db_sessionmaker, settings, "anna", TEST_PASSWORD, now=t0 + timedelta(minutes=16))
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


# --- Logout ------------------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.anyio
async def test_logout_revokes_only_the_current_session(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """logout ends the current session; the user's other devices stay logged in."""
    user = await user_factory(username="anna")
    first = await attempt(db_sessionmaker, settings, "anna", TEST_PASSWORD)
    second = await attempt(db_sessionmaker, settings, "anna", TEST_PASSWORD)
    current = CurrentUser(user.id, "anna", Role.user, first.session_id)
    async with db_sessionmaker() as db:
        await auth.logout(db, current, AuditContext.for_user(user.id, "anna"))
    async with db_sessionmaker() as db:
        active = {s.id for s in await sessions.list_active(db, user.id)}
    assert active == {second.session_id}


# --- First admin -------------------------------------------------------------------------------


@pytest.mark.db
@pytest.mark.anyio
async def test_initial_admin_is_created_once(
    db_sessionmaker: Sessionmaker, settings: Settings
) -> None:
    """The first admin is active, has role admin, and a second run changes nothing."""
    async with db_sessionmaker() as db:
        assert await ensure_initial_admin(db, settings) is True
    async with db_sessionmaker() as db:
        assert await ensure_initial_admin(db, settings) is False
    admin = await get_user(db_sessionmaker, settings.initial_admin_username)
    assert (admin.role, admin.status) == (Role.admin, UserStatus.active)
    assert await count_users(db_sessionmaker) == 1
    # The configured password works.
    tokens = await attempt(
        db_sessionmaker,
        settings,
        settings.initial_admin_username,
        settings.initial_admin_password.get_secret_value(),
    )
    assert tokens.role is Role.admin


@pytest.mark.db
@pytest.mark.anyio
async def test_initial_admin_is_safe_when_replicas_start_together(
    db_sessionmaker: Sessionmaker, settings: Settings
) -> None:
    """Two replicas running the check at once create exactly one account, without errors."""

    async def start() -> bool:
        async with db_sessionmaker() as db:
            return await ensure_initial_admin(db, settings)

    results = await asyncio.gather(start(), start(), start())
    assert sorted(results) == [False, False, True]
    assert await count_users(db_sessionmaker) == 1


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
