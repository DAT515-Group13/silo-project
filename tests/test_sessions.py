"""Session lifecycle and refresh rotation.

All tests need PostgreSQL (marker ``db``): rotation relies on ``SELECT ... FOR UPDATE``.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.config import Settings
from app.errors import InvalidToken, RefreshInProgress
from app.models import AuditLog, AuthSession, RefreshToken, Role, User, UserStatus
from app.security import decode_access_token, hash_token
from app.services import sessions
from tests.conftest import Sessionmaker, UserFactory

pytestmark = [pytest.mark.db, pytest.mark.anyio]


async def login(
    sm: Sessionmaker, settings: Settings, user: User, now: datetime | None = None
) -> sessions.IssuedTokens:
    """Create a session in its own transaction, like the login service does."""
    async with sm() as db, db.begin():
        return await sessions.create_session(db, settings, user, now=now)


async def load_session(sm: Sessionmaker, session_id: uuid.UUID) -> AuthSession:
    async with sm() as db:
        return await db.get_one(AuthSession, session_id)


async def rotate(sm: Sessionmaker, settings: Settings, token: str, now: datetime | None = None):
    """Rotate with a fresh database session, as each request would."""
    async with sm() as db:
        return await sessions.rotate_refresh(db, settings, token, now=now)


async def test_create_session_stores_only_the_hash(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """A new session has a usable access token and a refresh token stored as SHA-256 only.

    The session ends after SESSION_MAX_DAYS; the refresh token idles out after REFRESH_TOKEN_DAYS.
    """
    user = await user_factory(username="anna", role=Role.team_lead)
    now = datetime.now(UTC)
    tokens = await login(db_sessionmaker, settings, user, now)
    auth_session = await load_session(db_sessionmaker, tokens.session_id)
    assert auth_session.expires_at == now + timedelta(days=settings.session_max_days)
    assert tokens.refresh_expires_in == settings.refresh_token_days * 86400

    claims = decode_access_token(
        tokens.access_token,
        secrets=[settings.jwt_secret.get_secret_value()],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
    )
    assert (claims.user_id, claims.session_id) == (user.id, tokens.session_id)
    assert tokens.expires_in == settings.jwt_access_minutes * 60
    assert (tokens.username, tokens.role) == ("anna", Role.team_lead)

    async with db_sessionmaker() as db:
        stored = (await db.scalars(select(RefreshToken))).one()
    assert stored.token_hash == hash_token(tokens.refresh_token)
    assert stored.token_hash != tokens.refresh_token
    assert stored.used_at is None


async def test_refresh_token_never_outlives_the_session(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Near the session's end the new refresh token is cut to that end."""
    user = await user_factory()
    start = datetime.now(UTC)
    tokens = await login(db_sessionmaker, settings, user, start)
    # A refresh token lives 7 days, so reach the end of the 30-day session in steps of 6 days
    # (a single jump would find the first token expired). The last step is at day 24: 24 + 7 is
    # past the session's end at day 30, so that token must be cut to it.
    token, later = tokens.refresh_token, start
    for _ in range(4):
        later += timedelta(days=6)
        renewed = await rotate(db_sessionmaker, settings, token, later)
        token = renewed.refresh_token
    auth_session = await load_session(db_sessionmaker, tokens.session_id)
    async with db_sessionmaker() as db:
        successor = await db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_token(renewed.refresh_token))
        )
    assert successor is not None
    assert successor.expires_at == auth_session.expires_at
    assert successor.expires_at < later + timedelta(days=settings.refresh_token_days)


async def test_reuse_after_the_window_revokes_the_session(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """A token used again more than 10 s later revokes the session and is audited."""
    user = await user_factory()
    t0 = datetime.now(UTC)
    first = await login(db_sessionmaker, settings, user, t0)
    second = await rotate(db_sessionmaker, settings, first.refresh_token, t0)

    with pytest.raises(InvalidToken):
        await rotate(db_sessionmaker, settings, first.refresh_token, t0 + timedelta(seconds=11))

    # The revocation was committed although the call raised.
    auth_session = await load_session(db_sessionmaker, first.session_id)
    assert auth_session.revoked_at is not None
    assert auth_session.revoked_reason == "reuse_detected"
    async with db_sessionmaker() as db:
        entry = await db.scalar(select(AuditLog).where(AuditLog.action == "auth.refresh_reuse"))
    assert entry is not None
    assert (entry.outcome.value, entry.target_id) == ("denied", str(first.session_id))
    # The newest token of the stolen chain is dead too.
    with pytest.raises(InvalidToken):
        await rotate(db_sessionmaker, settings, second.refresh_token, t0 + timedelta(seconds=12))


async def test_concurrent_refresh_with_one_token(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Two parallel requests with the same token: one succeeds, the other gets 409 (row lock)."""
    user = await user_factory()
    first = await login(db_sessionmaker, settings, user)

    results = await asyncio.gather(
        rotate(db_sessionmaker, settings, first.refresh_token),
        rotate(db_sessionmaker, settings, first.refresh_token),
        return_exceptions=True,
    )

    successes = [r for r in results if isinstance(r, sessions.IssuedTokens)]
    conflicts = [r for r in results if isinstance(r, RefreshInProgress)]
    assert (len(successes), len(conflicts)) == (1, 1)
    assert (await load_session(db_sessionmaker, first.session_id)).revoked_at is None


async def test_unknown_expired_and_revoked_tokens_are_invalid(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Unknown token, idle-expired token, revoked session and disabled user: same InvalidToken."""
    user = await user_factory()
    t0 = datetime.now(UTC)
    tokens = await login(db_sessionmaker, settings, user, t0)
    second = await login(db_sessionmaker, settings, user, t0)

    with pytest.raises(InvalidToken):
        await rotate(db_sessionmaker, settings, "no-such-token")
    with pytest.raises(InvalidToken):
        late = t0 + timedelta(days=settings.refresh_token_days, seconds=1)
        await rotate(db_sessionmaker, settings, tokens.refresh_token, late)

    async with db_sessionmaker() as db, db.begin():
        await sessions.revoke(db, user.id, tokens.session_id)
    with pytest.raises(InvalidToken):
        await rotate(db_sessionmaker, settings, tokens.refresh_token)

    # The other session is still alive, but a user who is no longer active gets no new tokens.
    async with db_sessionmaker() as db, db.begin():
        (await db.get_one(User, user.id)).status = UserStatus.disabled
    with pytest.raises(InvalidToken):
        await rotate(db_sessionmaker, settings, second.refresh_token)


async def test_session_limit_revokes_the_least_recently_used(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """The 11th login revokes the least recently used session, not simply the oldest."""
    user = await user_factory()
    t0 = datetime.now(UTC) - timedelta(hours=1)
    created = [
        await login(db_sessionmaker, settings, user, t0 + timedelta(minutes=i)) for i in range(10)
    ]
    # The oldest device is in active use again, so the second oldest is now the least recent.
    async with db_sessionmaker() as db, db.begin():
        assert await sessions.touch(db, created[0].session_id, now=t0 + timedelta(minutes=30))

    newest = await login(db_sessionmaker, settings, user, t0 + timedelta(minutes=40))

    revoked = await load_session(db_sessionmaker, created[1].session_id)
    assert (revoked.revoked_reason, revoked.revoked_at is not None) == ("session_limit", True)
    async with db_sessionmaker() as db:
        active = await sessions.list_active(db, user.id, now=t0 + timedelta(minutes=41))
    assert len(active) == 10
    assert created[1].session_id not in {s.id for s in active}
    assert {created[0].session_id, newest.session_id} <= {s.id for s in active}
