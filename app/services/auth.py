"""Credentials: register, login with lockout, logout.

Sessions and tokens are in ``services/sessions.py``; this module decides who may log in.
Every function owns its transaction. Where a request must fail but its database changes must
stay (a wrong password increments the failure counter), the error is raised after the
transaction block, because an exception inside it would roll the change back.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.errors import (
    AccountDisabled,
    AccountPending,
    AccountRejected,
    InvalidCredentials,
    NotFound,
    SiloError,
    UsernameTaken,
    ValidationFailed,
)
from app.metrics import LOGIN_ATTEMPTS
from app.models import Outcome, Role, User, UserStatus
from app.permissions import CurrentUser
from app.security import (
    check_password_policy,
    hash_password,
    password_needs_rehash,
    verify_dummy_password,
    verify_password,
)
from app.services import audit, sessions
from app.services.audit import AuditAction, AuditContext
from app.services.sessions import IssuedTokens, RevokeReason

# Usernames are visible to other users, so anyone can lock an account on purpose (D25): the lock
# stays short. The per-IP rate limit on login still applies.
MAX_LOCK = timedelta(hours=1)

_INACTIVE_ERRORS: dict[UserStatus, type[SiloError]] = {
    UserStatus.pending: AccountPending,
    UserStatus.rejected: AccountRejected,
    UserStatus.disabled: AccountDisabled,
}


def lock_duration(settings: Settings, failed_login_count: int) -> timedelta:
    """Return how long the account is locked when the failure counter reaches this value.

    ``LOGIN_LOCK_MINUTES * 2^(count / LOGIN_MAX_FAILED - 1)``, at most 1 hour (D25): 15 minutes at
    10 failures, 30 at 20, 60 at 30, and so on. Only call it for multiples of LOGIN_MAX_FAILED.
    """
    exponent = failed_login_count // settings.login_max_failed - 1
    # min(exponent, 16): 2**16 minutes is far above the cap, and it keeps the number small.
    minutes = settings.login_lock_minutes * 2 ** min(max(exponent, 0), 16)
    return min(timedelta(minutes=minutes), MAX_LOCK)


async def register(
    session: AsyncSession,
    settings: Settings,
    username: str,
    password: str,
    *,
    ip: str | None = None,
    request_id: str | None = None,
    now: datetime | None = None,
) -> User | None:
    """Register an account according to ``REGISTRATION_MODE``.

    Returns the new (active) user in ``open`` mode and ``None`` in ``approval`` mode, where the
    caller always answers the same 202, whether or not the username was taken.

    Raises:
        NotFound: in ``closed`` mode.
        ValidationFailed: if the password breaks the policy.
        UsernameTaken: in ``open`` mode only.

    Side effects: inserts a user and writes ``auth.register`` (``approval`` mode with a taken
    username writes a ``denied`` entry instead).
    """
    now = now or datetime.now(UTC)
    if settings.registration_mode == "closed":
        raise NotFound
    check_password_policy(password, username, settings.password_min_length)

    # The password is hashed even if the username turns out to be taken, so the response time
    # does not reveal whether the account exists.
    password_hash = await hash_password(password)
    is_open = settings.registration_mode == "open"
    ctx = AuditContext.anonymous(ip=ip, request_id=request_id)

    async with session.begin():
        # One statement for both cases. ON CONFLICT DO NOTHING also covers two parallel
        # registrations of the same name: the unique constraint decides, nobody gets an error 500.
        user_id = await session.scalar(
            pg_insert(User)
            .values(
                username=username,
                password_hash=password_hash,
                role=Role.user,
                status=UserStatus.active if is_open else UserStatus.pending,
                approved_at=now if is_open else None,
            )
            .on_conflict_do_nothing(index_elements=["username"])
            .returning(User.id)
        )
        user = None
        if user_id is not None:
            user = await session.get_one(User, user_id)
            await audit.record(
                session,
                ctx,
                AuditAction.auth_register,
                target_type="user",
                target_id=user_id,
                target_label=username,
            )

    if user_id is None:
        if is_open:
            raise UsernameTaken
        # approval mode: log it, but answer exactly as for a successful registration.
        await audit.record_failure(
            session,
            ctx,
            AuditAction.auth_register,
            outcome=Outcome.denied,
            target_type="user",
            target_label=username,
            details={"reason": "username_taken"},
        )
        return None
    return user if is_open else None


async def login(
    session: AsyncSession,
    settings: Settings,
    username: str,
    password: str,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    now: datetime | None = None,
) -> IssuedTokens:
    """Check credentials and open a session.

    Raises:
        InvalidCredentials: unknown username, wrong password or locked account. All three look
            identical to the client.
        AccountPending, AccountRejected, AccountDisabled: correct password, but the account
            cannot log in (deliberately revealed only after the password was right).

    Side effects: failure counter and lock, rehash of an outdated password hash, session and
    tokens, audit entries (``auth.login``, ``auth.lockout``).
    """
    now = now or datetime.now(UTC)
    username = username.strip().lower()
    anonymous = AuditContext.anonymous(ip=ip, request_id=request_id)

    # Step 2: look up the user. Unknown username: spend the time of a real check anyway.
    async with session.begin():
        user = await session.scalar(select(User).where(User.username == username))
    if user is None:
        await verify_dummy_password(password)
        await audit.record_failure(
            session, anonymous, AuditAction.auth_login, outcome=Outcome.failed
        )
        LOGIN_ATTEMPTS.labels("invalid").inc()
        raise InvalidCredentials

    # Step 3: a locked account answers like a wrong password, even for the right password, and
    # the attempt is not counted, so nobody can extend someone else's lock by spamming it.
    if user.locked_until is not None and user.locked_until > now:
        await verify_dummy_password(password)
        # Not counted, but logged: a brute force attempt during the lock stays visible.
        await audit.record_failure(
            session,
            anonymous,
            AuditAction.auth_login,
            outcome=Outcome.denied,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
            details={"reason": "locked"},
        )
        LOGIN_ATTEMPTS.labels("locked").inc()
        raise InvalidCredentials

    password_ok = await verify_password(user.password_hash, password)

    # Step 4: wrong password -> count it, and lock the account at every LOGIN_MAX_FAILED-th failure.
    if not password_ok:
        target = {"target_type": "user", "target_id": user.id, "target_label": user.username}
        async with session.begin():
            # The condition lives in the UPDATE: if a parallel attempt locked the account in
            # the meantime, this one is not counted. RETURNING gives the counter atomically.
            count = await session.scalar(
                update(User)
                .where(
                    User.id == user.id, or_(User.locked_until.is_(None), User.locked_until <= now)
                )
                .values(failed_login_count=User.failed_login_count + 1)
                .returning(User.failed_login_count)
            )
            await audit.record(
                session, anonymous, AuditAction.auth_login, outcome=Outcome.failed, **target
            )
            if count is not None and count % settings.login_max_failed == 0:
                lock = lock_duration(settings, count)
                await session.execute(
                    update(User).where(User.id == user.id).values(locked_until=now + lock)
                )
                await audit.record(
                    session,
                    anonymous,
                    AuditAction.auth_lockout,
                    details={
                        "failed_login_count": count,
                        # total_seconds(): `.seconds` drops whole days, so 24 h would read 0.
                        "locked_minutes": int(lock.total_seconds() // 60),
                    },
                    **target,
                )
        # Raised after the block, so the counter and the lock are committed.
        LOGIN_ATTEMPTS.labels("invalid").inc()
        raise InvalidCredentials

    # Step 5: right password, but the account may not log in.
    if user.status != UserStatus.active:
        await audit.record_failure(
            session,
            anonymous,
            AuditAction.auth_login,
            outcome=Outcome.denied,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
            details={"status": user.status.value},
        )
        LOGIN_ATTEMPTS.labels("inactive").inc()
        raise _INACTIVE_ERRORS[user.status]

    # Step 6: success. Hashing happens before the transaction, which should stay short.
    new_hash = await hash_password(password) if password_needs_rehash(user.password_hash) else None
    async with session.begin():
        values: dict = {"failed_login_count": 0, "locked_until": None, "last_login_at": now}
        if new_hash is not None:
            values["password_hash"] = new_hash  # parameters changed since the hash was made
        await session.execute(update(User).where(User.id == user.id).values(**values))
        tokens = await sessions.create_session(
            session, settings, user, ip=ip, user_agent=user_agent, now=now
        )
        await audit.record(
            session,
            AuditContext.for_user(user.id, user.username, ip=ip, request_id=request_id),
            AuditAction.auth_login,
        )
    LOGIN_ATTEMPTS.labels("success").inc()
    return tokens


async def logout(
    session: AsyncSession, user: CurrentUser, ctx: AuditContext, *, now: datetime | None = None
) -> None:
    """Revoke the current session (POST /auth/logout). Its access token stops working at once."""
    async with session.begin():
        await sessions.revoke(session, user.id, user.session_id, RevokeReason.logout, now=now)
        await audit.record(
            session,
            ctx,
            AuditAction.auth_logout,
            target_type="session",
            target_id=user.session_id,
        )


async def logout_all(
    session: AsyncSession, user: CurrentUser, ctx: AuditContext, *, now: datetime | None = None
) -> int:
    """Revoke all sessions of the user, including the current one. Returns how many."""
    async with session.begin():
        revoked = await sessions.revoke_all(session, user.id, RevokeReason.logout_all, now=now)
        await audit.record(session, ctx, AuditAction.auth_logout_all, details={"revoked": revoked})
    return revoked


async def revoke_own_session(
    session: AsyncSession,
    user: CurrentUser,
    session_id: uuid.UUID,
    ctx: AuditContext,
    *,
    now: datetime | None = None,
) -> None:
    """Revoke one of the user's own sessions (DELETE /auth/sessions/{id}).

    Raises:
        NotFound: the session is unknown, not the user's own, or already over.
    """
    async with session.begin():
        await sessions.revoke(session, user.id, session_id, RevokeReason.logout, now=now)
        await audit.record(
            session,
            ctx,
            AuditAction.auth_session_revoke,
            target_type="session",
            target_id=session_id,
        )


async def change_password(
    session: AsyncSession,
    settings: Settings,
    user: CurrentUser,
    ctx: AuditContext,
    current_password: str,
    new_password: str,
    *,
    now: datetime | None = None,
) -> int:
    """Change the user's own password (POST /me/password). Returns how many other sessions ended.

    The current session stays signed in; every other session of the user is revoked.

    Raises:
        ValidationFailed: the new password breaks the policy, or ``current_password`` is wrong
            (field ``current_password``). Not 401: a client must not mistake it for a dead token.
    """
    check_password_policy(
        new_password, user.username, settings.password_min_length, field="new_password"
    )
    async with session.begin():
        old_hash = await session.scalar(select(User.password_hash).where(User.id == user.id))
    changed = False
    revoked = 0
    if old_hash is not None and await verify_password(old_hash, current_password):
        new_hash = await hash_password(new_password)
        async with session.begin():
            # The old hash is part of the condition: of two parallel changes with the same
            # current password only one updates a row, the other counts as a wrong password.
            updated = await session.scalar(
                update(User)
                .where(User.id == user.id, User.password_hash == old_hash)
                .values(password_hash=new_hash)
                .returning(User.id)
            )
            if updated is not None:
                changed = True
                revoked = await sessions.revoke_all(
                    session, user.id, RevokeReason.password_change, keep=user.session_id, now=now
                )
                await audit.record(
                    session,
                    ctx,
                    AuditAction.auth_password_change,
                    target_type="user",
                    target_id=user.id,
                    target_label=user.username,
                    details={"revoked": revoked},
                )
    if not changed:
        await audit.record_failure(
            session,
            ctx,
            AuditAction.auth_password_change,
            outcome=Outcome.failed,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
        )
        raise ValidationFailed(
            [{"field": "current_password", "message": "Current password is wrong."}]
        )
    return revoked
