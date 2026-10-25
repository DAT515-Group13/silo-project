"""Session lifecycle and refresh rotation.

All tests need PostgreSQL (marker ``db``): rotation relies on ``SELECT ... FOR UPDATE``.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.config import Settings
from app.errors import InvalidToken, NotFound, RefreshInProgress
from app.models import AuditLog, AuthSession, RefreshToken, Role, User, UserStatus
from app.security import decode_access_token, hash_token
from app.services import sessions
from app.services.sessions import RevokeReason
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
    """A new session has a usable access token and a refresh token stored as SHA-256 only."""
    user = await user_factory(username="anna", role=Role.team_lead)
    tokens = await login(db_sessionmaker, settings, user)

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


async def test_session_and_refresh_lifetimes(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Session ends after SESSION_MAX_DAYS; the refresh token idles out after REFRESH_TOKEN_DAYS."""
    user = await user_factory()
    now = datetime.now(UTC)
    tokens = await login(db_sessionmaker, settings, user, now)
    auth_session = await load_session(db_sessionmaker, tokens.session_id)
    assert auth_session.expires_at == now + timedelta(days=settings.session_max_days)
    assert tokens.refresh_expires_in == settings.refresh_token_days * 86400


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


async def test_rotation_marks_the_old_token_and_links_the_new_one(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Rotation sets used_at on the old token, replaced_by_id to the new one, and audits it."""
    user = await user_factory()
    first = await login(db_sessionmaker, settings, user)
    second = await rotate(db_sessionmaker, settings, first.refresh_token)

    assert second.refresh_token != first.refresh_token
    assert second.session_id == first.session_id
    async with db_sessionmaker() as db:
        old = await db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_token(first.refresh_token))
        )
        new = await db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == hash_token(second.refresh_token))
        )
        actions = (await db.scalars(select(AuditLog.action))).all()
    assert old is not None and new is not None
    assert old.used_at is not None
    assert old.replaced_by_id == new.id
    assert actions == ["auth.refresh"]
    # The new token works for the next rotation.
    await rotate(db_sessionmaker, settings, second.refresh_token)


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


async def test_reuse_within_the_window_is_a_conflict_without_revoking(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Within 10 s a second use gives 409 refresh_in_progress and changes nothing."""
    user = await user_factory()
    t0 = datetime.now(UTC)
    first = await login(db_sessionmaker, settings, user, t0)
    second = await rotate(db_sessionmaker, settings, first.refresh_token, t0)

    with pytest.raises(RefreshInProgress):
        await rotate(db_sessionmaker, settings, first.refresh_token, t0 + timedelta(seconds=10))

    assert (await load_session(db_sessionmaker, first.session_id)).revoked_at is None
    await rotate(db_sessionmaker, settings, second.refresh_token, t0 + timedelta(seconds=10))


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
    """Unknown token, idle-expired token and revoked session all give the same InvalidToken."""
    user = await user_factory()
    t0 = datetime.now(UTC)
    tokens = await login(db_sessionmaker, settings, user, t0)

    with pytest.raises(InvalidToken):
        await rotate(db_sessionmaker, settings, "no-such-token")
    with pytest.raises(InvalidToken):
        late = t0 + timedelta(days=settings.refresh_token_days, seconds=1)
        await rotate(db_sessionmaker, settings, tokens.refresh_token, late)

    async with db_sessionmaker() as db, db.begin():
        await sessions.revoke(db, user.id, tokens.session_id)
    with pytest.raises(InvalidToken):
        await rotate(db_sessionmaker, settings, tokens.refresh_token)


async def test_disabled_user_cannot_refresh(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """A user who is no longer active gets no new tokens."""
    user = await user_factory()
    tokens = await login(db_sessionmaker, settings, user)
    async with db_sessionmaker() as db, db.begin():
        (await db.get_one(User, user.id)).status = UserStatus.disabled
    with pytest.raises(InvalidToken):
        await rotate(db_sessionmaker, settings, tokens.refresh_token)


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


async def test_session_limit_breaks_ties_by_created_at(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """With equal last_used_at the session created first is revoked."""
    user = await user_factory()
    t0 = datetime.now(UTC)
    created = [await login(db_sessionmaker, settings, user, t0) for _ in range(10)]
    # Same last_used_at for all; created_at is made distinct and increasing.
    async with db_sessionmaker() as db, db.begin():
        for index, tokens in enumerate(created):
            (await db.get_one(AuthSession, tokens.session_id)).created_at = t0 + timedelta(
                seconds=index
            )
    await login(db_sessionmaker, settings, user, t0)
    assert (await load_session(db_sessionmaker, created[0].session_id)).revoked_at is not None
    assert (await load_session(db_sessionmaker, created[1].session_id)).revoked_at is None


async def test_list_active_and_revoke_are_limited_to_the_owner(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """Only own, active sessions are listed or revocable; others and unknown ones are NotFound."""
    anna = await user_factory(username="anna")
    bob = await user_factory(username="bob")
    mine = await login(db_sessionmaker, settings, anna)
    other = await login(db_sessionmaker, settings, bob)

    async with db_sessionmaker() as db:
        listed = await sessions.list_active(db, anna.id)
    assert [s.id for s in listed] == [mine.session_id]

    for target in (other.session_id, uuid.uuid4()):
        with pytest.raises(NotFound):
            async with db_sessionmaker() as db, db.begin():
                await sessions.revoke(db, anna.id, target)

    async with db_sessionmaker() as db, db.begin():
        await sessions.revoke(db, anna.id, mine.session_id)
    # Revoking twice is NotFound as well: the session is no longer active.
    with pytest.raises(NotFound):
        async with db_sessionmaker() as db, db.begin():
            await sessions.revoke(db, anna.id, mine.session_id)
    async with db_sessionmaker() as db:
        assert await sessions.list_active(db, anna.id) == []


async def test_revoke_all_can_keep_one_session(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """revoke_all ends every active session of the user, except the one named in keep."""
    user = await user_factory()
    a = await login(db_sessionmaker, settings, user)
    b = await login(db_sessionmaker, settings, user)
    async with db_sessionmaker() as db, db.begin():
        count = await sessions.revoke_all(db, user.id, RevokeReason.logout_all, keep=a.session_id)
    assert count == 1
    assert (await load_session(db_sessionmaker, a.session_id)).revoked_at is None
    revoked = await load_session(db_sessionmaker, b.session_id)
    assert revoked.revoked_reason == "logout_all"
    async with db_sessionmaker() as db, db.begin():
        assert await sessions.revoke_all(db, user.id, RevokeReason.admin) == 1


async def test_revoke_all_skips_expired_sessions(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """An expired session is not counted and keeps no revocation reason."""
    user = await user_factory()
    old = await login(
        db_sessionmaker,
        settings,
        user,
        datetime.now(UTC) - timedelta(days=settings.session_max_days + 1),
    )
    await login(db_sessionmaker, settings, user)
    async with db_sessionmaker() as db, db.begin():
        assert await sessions.revoke_all(db, user.id, RevokeReason.logout_all) == 1
    assert (await load_session(db_sessionmaker, old.session_id)).revoked_at is None


async def test_touch_updates_last_used_at_at_most_once_a_minute(
    db_sessionmaker: Sessionmaker, settings: Settings, user_factory: UserFactory
) -> None:
    """last_used_at changes only when the last value is a minute old."""
    user = await user_factory()
    t0 = datetime.now(UTC)
    tokens = await login(db_sessionmaker, settings, user, t0)

    async def touch(at: datetime) -> bool:
        async with db_sessionmaker() as db, db.begin():
            return await sessions.touch(db, tokens.session_id, now=at)

    assert await touch(t0 + timedelta(seconds=30)) is False
    assert await touch(t0 + timedelta(seconds=60)) is True
    assert await touch(t0 + timedelta(seconds=90)) is False
    assert (await load_session(db_sessionmaker, tokens.session_id)).last_used_at == t0 + timedelta(
        seconds=60
    )
