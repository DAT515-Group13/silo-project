"""Session lifecycle: create, refresh rotation with reuse detection, list, revoke.

One database session (``auth_sessions`` row) exists per logged-in device. Access tokens are
valid only while their session is active, which is how logout takes effect immediately.

Transactions: ``rotate_refresh`` and ``list_active`` run their own transaction. The other
functions are building blocks (login, logout, admin actions) and run inside the caller's
transaction, so that for example "disable user" and "revoke all sessions" commit together.
"""

import enum
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.errors import InvalidToken, NotFound, RefreshInProgress
from app.models import AuthSession, Outcome, RefreshToken, Role, User, UserStatus
from app.security import create_access_token, generate_refresh_token, hash_token
from app.services import audit
from app.services.audit import AuditAction, AuditContext

MAX_ACTIVE_SESSIONS = 10
# A refresh token used again within this window is a parallel request, not theft.
REFRESH_REUSE_GRACE = timedelta(seconds=10)
# session.last_used_at is written at most this often.
LAST_USED_UPDATE_INTERVAL = timedelta(minutes=1)


class RevokeReason(enum.StrEnum):
    """Values of ``auth_sessions.revoked_reason``."""

    logout = "logout"
    logout_all = "logout_all"
    reuse_detected = "reuse_detected"
    user_disabled = "user_disabled"
    admin = "admin"
    session_limit = "session_limit"


@dataclass(frozen=True)
class IssuedTokens:
    """A new token pair and the facts the response needs (example 9.1)."""

    access_token: str
    refresh_token: str
    expires_in: int
    refresh_expires_in: int
    session_id: uuid.UUID
    user_id: int
    username: str
    role: Role


def _new_refresh_token(
    settings: Settings, auth_session: AuthSession, now: datetime
) -> tuple[RefreshToken, str]:
    """Build a refresh token row and return it with the plain token (stored only as a hash).

    The idle lifetime is ``REFRESH_TOKEN_DAYS`` but never later than the session's own end,
    so a refresh token cannot extend a session beyond ``SESSION_MAX_DAYS``.
    """
    plain = generate_refresh_token()
    expires_at = min(now + timedelta(days=settings.refresh_token_days), auth_session.expires_at)
    row = RefreshToken(
        session_id=auth_session.id,
        token_hash=hash_token(plain),
        created_at=now,
        expires_at=expires_at,
    )
    return row, plain


def _issue(
    settings: Settings,
    user: User,
    auth_session: AuthSession,
    refresh: RefreshToken,
    plain_refresh: str,
    now: datetime,
) -> IssuedTokens:
    """Create the access token and bundle it with the refresh token."""
    ttl = timedelta(minutes=settings.jwt_access_minutes)
    access = create_access_token(
        user_id=user.id,
        session_id=auth_session.id,
        secret=settings.jwt_secret.get_secret_value(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl=ttl,
        now=now,
    )
    return IssuedTokens(
        access_token=access,
        refresh_token=plain_refresh,
        expires_in=int(ttl.total_seconds()),
        refresh_expires_in=int((refresh.expires_at - now).total_seconds()),
        session_id=auth_session.id,
        user_id=user.id,
        username=user.username,
        role=user.role,
    )


async def create_session(
    session: AsyncSession,
    settings: Settings,
    user: User,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
    now: datetime | None = None,
) -> IssuedTokens:
    """Create a session with its first refresh token and enforce the limit of 10 sessions.

    Runs in the caller's transaction (the login service). If the user now has more than 10
    active sessions, the least recently used ones are revoked as ``session_limit`` (login step 6).
    """
    now = now or datetime.now(UTC)

    # Step 1: lock the user row, so two parallel logins cannot both pass the session limit.
    await session.scalar(select(User.id).where(User.id == user.id).with_for_update())

    # Step 2: the session and its first refresh token.
    auth_session = AuthSession(
        id=uuid.uuid4(),
        user_id=user.id,
        created_at=now,
        last_used_at=now,
        expires_at=now + timedelta(days=settings.session_max_days),
        ip=ip,
        user_agent=user_agent[:255] if user_agent else None,
    )
    refresh, plain = _new_refresh_token(settings, auth_session, now)
    session.add(auth_session)
    await session.flush()  # the session row must exist before the token row that references it
    session.add(refresh)
    await session.flush()

    # Step 3: more than 10 active sessions -> revoke the least recently used (ties: oldest).
    # An actively used old device keeps its session; the new session is never the victim.
    active = await session.scalars(
        select(AuthSession.id)
        .where(
            AuthSession.user_id == user.id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
        .order_by(AuthSession.last_used_at.asc(), AuthSession.created_at.asc())
    )
    candidates = [session_id for session_id in active if session_id != auth_session.id]
    excess = len(candidates) + 1 - MAX_ACTIVE_SESSIONS
    if excess > 0:
        await session.execute(
            update(AuthSession)
            .where(AuthSession.id.in_(candidates[:excess]))
            .values(revoked_at=now, revoked_reason=RevokeReason.session_limit.value)
        )

    return _issue(settings, user, auth_session, refresh, plain, now)


async def rotate_refresh(
    session: AsyncSession,
    settings: Settings,
    refresh_token: str,
    *,
    ip: str | None = None,
    request_id: str | None = None,
    now: datetime | None = None,
) -> IssuedTokens:
    """Exchange a refresh token for a new token pair.

    Owns its transaction. Raises:
        InvalidToken: unknown or expired token, revoked or expired session, inactive user, or a
            token that was already used more than 10 s ago. In the last case the session is
            revoked and the revocation is committed before the error is raised.
        RefreshInProgress: the token was used within the last 10 s (a parallel request); nothing
            is changed.

    Side effects: marks the old token used, adds its successor, updates the session's
    ``last_used_at`` and writes ``auth.refresh`` or ``auth.refresh_reuse``.
    """
    now = now or datetime.now(UTC)

    async with session.begin():
        # Step 1: look the token up by its hash and lock the row. A parallel request with the
        # same token waits here and then sees `used_at` set, which gives the 409 below.
        token = await session.scalar(
            select(RefreshToken)
            .where(RefreshToken.token_hash == hash_token(refresh_token))
            .with_for_update()
        )

        # Step 2: unknown, expired, or its session revoked or expired -> same 401 for all.
        if token is None or token.expires_at <= now:
            raise InvalidToken
        row = (
            await session.execute(
                select(AuthSession, User)
                .join(User, User.id == AuthSession.user_id)
                .where(AuthSession.id == token.session_id)
            )
        ).one()
        auth_session: AuthSession = row[0]
        user: User = row[1]
        if auth_session.revoked_at is not None or auth_session.expires_at <= now:
            raise InvalidToken
        ctx = AuditContext.for_user(user.id, user.username, ip=ip, request_id=request_id)

        # Step 3: the token was already used.
        if token.used_at is not None:
            if now - token.used_at <= REFRESH_REUSE_GRACE:
                # Two requests with the same token raced: not an attack, so nothing is revoked.
                raise RefreshInProgress
            # Used again after the grace window: the token was probably stolen. Kill the session.
            auth_session.revoked_at = now
            auth_session.revoked_reason = RevokeReason.reuse_detected.value
            await audit.record(
                session,
                ctx,
                AuditAction.auth_refresh_reuse,
                outcome=Outcome.denied,
                target_type="session",
                target_id=auth_session.id,
            )
            # Do not raise here: leaving the block commits the revocation and the audit entry.
        else:
            # Step 4: rotate. A user who was disabled meanwhile gets no new tokens.
            if user.status != UserStatus.active:
                raise InvalidToken
            successor, plain = _new_refresh_token(settings, auth_session, now)
            session.add(successor)
            await session.flush()
            token.used_at = now
            token.replaced_by_id = successor.id
            auth_session.last_used_at = now
            await audit.record(
                session,
                ctx,
                AuditAction.auth_refresh,
                target_type="session",
                target_id=auth_session.id,
            )
            return _issue(settings, user, auth_session, successor, plain, now)

    # Only the reuse branch gets here (every other path returned or raised inside the block).
    # Its revocation is committed now, so the client can get its 401.
    raise InvalidToken


async def list_active(
    session: AsyncSession, user_id: int, *, now: datetime | None = None
) -> list[AuthSession]:
    """Return the user's active sessions, most recently used first (GET /auth/sessions).

    Owns its (read-only) transaction.
    """
    now = now or datetime.now(UTC)
    async with session.begin():
        result = await session.scalars(
            select(AuthSession)
            .where(
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
            )
            .order_by(AuthSession.last_used_at.desc())
        )
        return list(result)


async def revoke(
    session: AsyncSession,
    user_id: int,
    session_id: uuid.UUID,
    reason: RevokeReason = RevokeReason.logout,
    *,
    now: datetime | None = None,
) -> None:
    """Revoke one active session of the given user. Runs in the caller's transaction.

    Raises:
        NotFound: if the session does not exist, belongs to someone else, or is already over.
            Same answer for all three, so session IDs cannot be probed.
    """
    now = now or datetime.now(UTC)
    result = await session.execute(
        update(AuthSession)
        .where(
            AuthSession.id == session_id,
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
        .values(revoked_at=now, revoked_reason=reason.value)
        .returning(AuthSession.id)
    )
    if result.first() is None:
        raise NotFound


async def revoke_all(
    session: AsyncSession,
    user_id: int,
    reason: RevokeReason,
    *,
    keep: uuid.UUID | None = None,
    now: datetime | None = None,
) -> int:
    """Revoke all active sessions of a user (logout-all, disable, admin). Caller's transaction.

    ``keep`` leaves one session alone. Returns the number of revoked sessions. Sessions that
    already expired are left as they are, so the count (written to the audit log) is right.
    """
    now = now or datetime.now(UTC)
    statement = (
        update(AuthSession)
        .where(
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
        .values(revoked_at=now, revoked_reason=reason.value)
        .returning(AuthSession.id)
    )
    if keep is not None:
        statement = statement.where(AuthSession.id != keep)
    return len((await session.execute(statement)).all())


async def touch(
    session: AsyncSession, session_id: uuid.UUID, *, now: datetime | None = None
) -> bool:
    """Set ``last_used_at`` to now, but at most once a minute. Caller's transaction.

    The condition is part of the UPDATE, so frequent requests cost one cheap statement and no
    row is rewritten more than once per minute. Returns True if the row was updated.
    """
    now = now or datetime.now(UTC)
    result = await session.execute(
        update(AuthSession)
        .where(
            AuthSession.id == session_id,
            AuthSession.last_used_at <= now - LAST_USED_UPDATE_INTERVAL,
        )
        .values(last_used_at=now)
        .returning(AuthSession.id)
    )
    return result.first() is not None
