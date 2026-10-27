"""User management: storage quotas, admin user actions and the first admin.

Implements the quota rules, the admin endpoints with their rules (last admin, disabling
revokes sessions, deleting a user deletes their blobs) and the "First admin" rule.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import Case, ScalarSelect, case, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.errors import InvalidUserState, LastAdmin, NotFound, QuotaExceeded, StorageFull
from app.models import File, Role, User, UserStatus
from app.permissions import CurrentUser, is_admin
from app.security import hash_password
from app.services import audit, sessions
from app.services.audit import AuditAction, AuditContext
from app.services.pagination import fetch_page
from app.services.sessions import RevokeReason

logger = logging.getLogger("silo")

DELETE_CONCURRENCY = 16


async def get_user(session: AsyncSession, user_id: int) -> User:
    """Load a user by ID in its own transaction (for example for ``GET /me``).

    Raises:
        NotFound: if the user does not exist (cannot happen for an authenticated request).
    """
    async with session.begin():
        user = await session.get(User, user_id)
    if user is None:
        raise NotFound
    return user


# --- Quotas ------------------------------------------------------------------


@dataclass(frozen=True)
class QuotaStatus:
    """A user's storage usage and the quota of their current role, in bytes."""

    used_bytes: int
    quota_bytes: int

    @property
    def remaining(self) -> int:
        """Bytes that still fit. Never negative: a lowered role can leave usage above the quota."""
        return max(0, self.quota_bytes - self.used_bytes)

    @property
    def can_upload(self) -> bool:
        """False once usage reaches the quota; then new uploads are blocked."""
        return self.remaining > 0


def quota_case(settings: Settings) -> Case:
    """SQL expression for the quota of the row's role, built from ``Settings.quota_for_role``.

    The quota is computed inside the UPDATE itself (not passed in from an earlier read), so a
    role change between reading the status and reserving cannot be bypassed.
    """
    # `User.role == role` binds each value with the column's enum type; a plain `value=` mapping
    # would send untyped parameters.
    return case(*[(User.role == role, settings.quota_for_role(role)) for role in Role])


async def get_quota_status(session: AsyncSession, settings: Settings, user_id: int) -> QuotaStatus:
    """Read the user's usage and quota in its own read-only transaction (upload step 2).

    Only a hint for streaming: the binding check is ``reserve_quota``.

    Raises:
        NotFound: if the user does not exist.
    """
    async with session.begin():
        row = (
            await session.execute(select(User.used_bytes, User.role).where(User.id == user_id))
        ).first()
    if row is None:
        raise NotFound
    return QuotaStatus(used_bytes=row.used_bytes, quota_bytes=settings.quota_for_role(row.role))


async def reserve_quota(session: AsyncSession, settings: Settings, user_id: int, size: int) -> int:
    """Add ``size`` bytes to the user's usage if they fit into the quota (upload step 4).

    Runs inside the caller's ``session.begin()`` block, together with the insert of the
    ``files`` row and the audit entry, and never commits.

    Returns:
        The new ``used_bytes``.

    Raises:
        QuotaExceeded: the bytes do not fit (for example a parallel upload used the space).
        ValueError: if ``size`` is negative (a programming error, not user input).
    """
    if size < 0:
        raise ValueError("size must not be negative")
    # Atomic quota update: check and increment are one statement. PostgreSQL
    # locks the row, and a parallel UPDATE re-checks the WHERE condition against the committed
    # value, so two uploads at the quota edge can never both succeed.
    used = await session.scalar(
        update(User)
        .where(User.id == user_id, User.used_bytes + size <= quota_case(settings))
        .values(used_bytes=User.used_bytes + size)
        .returning(User.used_bytes)
    )
    if used is None:
        # No row: over the quota (or an unknown user, which a logged-in uploader cannot be).
        raise QuotaExceeded
    return used


# Key of the advisory lock that serialises the global storage check. Any fixed number works; it
# only has to be the same in every process.
_GLOBAL_QUOTA_LOCK = 51515


async def total_used_bytes(session: AsyncSession) -> int:
    """Return the sum of ``used_bytes`` over all users, inside the caller's transaction."""
    return await session.scalar(select(func.coalesce(func.sum(User.used_bytes), 0))) or 0


async def get_global_remaining(session: AsyncSession, settings: Settings) -> int | None:
    """Return the bytes left under ``STORAGE_TOTAL_MAX_BYTES`` (upload step 2), or None if off.

    Read in its own transaction and only a hint for streaming: the binding check is
    ``reserve_global``. Never negative.
    """
    cap = settings.global_cap()
    if cap is None:
        return None
    async with session.begin():
        used = await total_used_bytes(session)
    return max(cap - used, 0)


async def reserve_global(session: AsyncSession, settings: Settings, size: int) -> None:
    """Check that ``size`` more bytes fit under ``STORAGE_TOTAL_MAX_BYTES`` (upload step 4).

    Runs inside the caller's ``session.begin()`` block, before ``reserve_quota``, and does
    nothing when the cap is off.

    Raises:
        StorageFull: the total would pass the cap.
    """
    cap = settings.global_cap()
    if cap is None:
        return
    # The per-user UPDATE locks only that user's row, so two users at the global edge could
    # both see room and both commit. This lock serialises the short step-4 transactions of all
    # uploads; PostgreSQL releases it at commit or rollback. The sum below is read after the
    # lock is held, so (READ COMMITTED) it includes everything the previous holder committed.
    # Deletes need no lock: they only lower the sum.
    await session.execute(select(func.pg_advisory_xact_lock(_GLOBAL_QUOTA_LOCK)))
    if await total_used_bytes(session) + size > cap:
        raise StorageFull


async def release_quota(session: AsyncSession, user_id: int, size: int) -> None:
    """Subtract ``size`` bytes from the user's usage (file delete).

    Runs in the caller's transaction, the same one that deletes the ``files`` row, so usage and
    files never disagree. The ``used_bytes >= 0`` CHECK constraint turns an accounting bug into
    an error instead of a negative counter.

    Raises:
        ValueError: if ``size`` is negative.
    """
    if size < 0:
        raise ValueError("size must not be negative")
    await session.execute(
        update(User).where(User.id == user_id).values(used_bytes=User.used_bytes - size)
    )


# --- Admin user management ------------------------------------------------


class BlobDeleter(Protocol):
    """The part of the BlobStore that ``delete_user`` needs."""

    async def delete(self, blob_name: str) -> None:
        """Delete one blob; idempotent; raises ``StorageUnavailable`` on storage errors."""
        ...


@dataclass(frozen=True)
class UserWithFiles:
    """A user row and the number of files they own (the admin list warns before deleting)."""

    user: User
    file_count: int


def _require_admin(actor: CurrentUser) -> None:
    """Permission check of every admin function: non-admins get 404, not 403."""
    if not is_admin(actor):
        raise NotFound


async def _lock_target(session: AsyncSession, user_id: int) -> User:
    """Load and lock the user an admin acts on, or raise ``NotFound``.

    ``populate_existing``: the request's session keeps objects across transactions
    (``expire_on_commit=False``), and without it a locked re-read would return the copy loaded
    earlier instead of the row as it is now.
    """
    user = await session.scalar(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if user is None:
        raise NotFound
    return user


async def _lock_active_admins(session: AsyncSession) -> set[int]:
    """Lock every active admin row and return their IDs (last-admin rule).

    Two admins demoting or disabling each other at the same time would otherwise each see the
    other one as "another active admin" and both succeed. With the rows locked, the second
    transaction waits and then counts again. Always taken before the target's lock, in ID
    order, so two admin actions cannot deadlock.
    """
    rows = await session.scalars(
        select(User.id)
        .where(User.role == Role.admin, User.status == UserStatus.active)
        .order_by(User.id)
        .with_for_update()
    )
    return set(rows)


def _check_last_admin(actor: CurrentUser, target: User, active_admins: set[int]) -> None:
    """Refuse to delete, disable or demote yourself or the last active admin.

    Only call it for an action that removes ``target``'s admin power.

    Raises:
        LastAdmin: in both cases (one code).
    """
    if target.id == actor.id:
        raise LastAdmin
    if target.id in active_admins and len(active_admins) <= 1:
        raise LastAdmin


def _file_count() -> ScalarSelect[int]:
    """Correlated subquery: number of files owned by the user of the row."""
    return select(func.count(File.id)).where(File.owner_id == User.id).scalar_subquery()


async def list_users(
    session: AsyncSession,
    actor: CurrentUser,
    *,
    status: UserStatus | None = None,
    page: int,
    size: int,
) -> tuple[list[UserWithFiles], int]:
    """All users, newest first, optionally filtered by status (GET /admin/users).

    Raises:
        NotFound: the actor is not an admin.
    """
    _require_admin(actor)
    async with session.begin():
        statement = select(User, _file_count().label("file_count")).order_by(
            User.created_at.desc(), User.id.desc()
        )
        if status is not None:
            statement = statement.where(User.status == status)
        rows, total = await fetch_page(session, statement, page=page, size=size)
    return [UserWithFiles(user=row[0], file_count=row[1]) for row in rows], total


async def approve_user(
    session: AsyncSession,
    actor: CurrentUser,
    user_id: int,
    ctx: AuditContext,
    *,
    now: datetime | None = None,
) -> None:
    """Approve a pending registration: ``pending`` -> ``active`` (POST /admin/users/{id}/approve).

    Raises:
        NotFound: the actor is not an admin, or the user does not exist.
        InvalidUserState: the user is not ``pending`` (D18).

    Side effects: sets ``approved_by`` and ``approved_at``, writes ``user.approve``.
    """
    _require_admin(actor)
    now = now or datetime.now(UTC)
    async with session.begin():
        target = await _lock_target(session, user_id)
        if target.status != UserStatus.pending:
            raise InvalidUserState
        target.status = UserStatus.active
        target.approved_by = actor.id
        target.approved_at = now
        await audit.record(
            session,
            ctx,
            AuditAction.user_approve,
            target_type="user",
            target_id=target.id,
            target_label=target.username,
        )


async def reject_user(
    session: AsyncSession,
    actor: CurrentUser,
    user_id: int,
    ctx: AuditContext,
    *,
    reason: str | None = None,
) -> None:
    """Reject a pending registration: ``pending`` -> ``rejected`` (POST .../reject).

    The account stays in the table, so the same username cannot simply register again.

    Raises:
        NotFound: the actor is not an admin, or the user does not exist.
        InvalidUserState: the user is not ``pending`` (D18).

    Side effects: revokes all sessions (a pending account has none, but the spec asks for it
    on every rejection), writes ``user.reject`` with ``details.reason``.
    """
    _require_admin(actor)
    async with session.begin():
        target = await _lock_target(session, user_id)
        if target.status != UserStatus.pending:
            raise InvalidUserState
        target.status = UserStatus.rejected
        await sessions.revoke_all(session, target.id, RevokeReason.admin)
        await audit.record(
            session,
            ctx,
            AuditAction.user_reject,
            target_type="user",
            target_id=target.id,
            target_label=target.username,
            details={"reason": reason} if reason else None,
        )


async def update_user(
    session: AsyncSession,
    actor: CurrentUser,
    user_id: int,
    ctx: AuditContext,
    *,
    role: Role | None = None,
    status: UserStatus | None = None,
) -> User:
    """Change a user's role and/or status (PATCH /admin/users/{id}).

    ``status`` may only switch between ``active`` and ``disabled``; the schema allows nothing
    else. A role change takes effect on the user's next request (the role is never in the
    token). Values equal to the current ones change nothing and write no audit entry.

    Raises:
        NotFound: the actor is not an admin, or the user does not exist.
        InvalidUserState: a status change for a ``pending`` or ``rejected`` user (use approve).
        LastAdmin: demoting or disabling yourself or the last active admin.
        ValueError: ``status`` other than ``active`` or ``disabled`` (a programming error).

    Side effects: disabling revokes all the user's sessions in the same transaction (reason
    ``user_disabled``), so their access tokens stop working at once; writes
    ``user.role_change``, ``user.deactivate`` or ``user.activate``.
    """
    _require_admin(actor)
    if status not in (None, UserStatus.active, UserStatus.disabled):
        raise ValueError("status can only be set to active or disabled")

    async with session.begin():
        active_admins = await _lock_active_admins(session)
        target = await _lock_target(session, user_id)
        role_changes = role is not None and role != target.role
        status_changes = status is not None and status != target.status
        if status_changes and target.status not in (UserStatus.active, UserStatus.disabled):
            raise InvalidUserState

        # Business rule: an admin who loses the role or gets disabled must not be the actor or
        # the last active admin.
        demoted = role_changes and target.role == Role.admin
        disabled = status_changes and status == UserStatus.disabled
        # (The actor is an active admin, so acting on yourself is always covered here.)
        if (demoted or disabled) and target.role == Role.admin:
            _check_last_admin(actor, target, active_admins)

        label = {"target_type": "user", "target_id": target.id, "target_label": target.username}
        if role_changes:
            old_role = target.role
            target.role = role
            await audit.record(
                session,
                ctx,
                AuditAction.user_role_change,
                details={"from": old_role.value, "to": role.value},
                **label,
            )
        if status_changes and status == UserStatus.disabled:
            target.status = status
            revoked = await sessions.revoke_all(session, target.id, RevokeReason.user_disabled)
            await audit.record(
                session,
                ctx,
                AuditAction.user_deactivate,
                details={"sessions_revoked": revoked},
                **label,
            )
        elif status_changes:
            target.status = status
            await audit.record(session, ctx, AuditAction.user_activate, **label)
        await session.flush()
        return target


async def revoke_user_sessions(
    session: AsyncSession, actor: CurrentUser, user_id: int, ctx: AuditContext
) -> int:
    """Log a user out everywhere (POST /admin/users/{id}/revoke-sessions). Returns the count.

    Raises:
        NotFound: the actor is not an admin, or the user does not exist.

    Side effects: revokes all active sessions with reason ``admin``, writes
    ``user.sessions_revoke``.
    """
    _require_admin(actor)
    async with session.begin():
        target = await _lock_target(session, user_id)
        revoked = await sessions.revoke_all(session, target.id, RevokeReason.admin)
        await audit.record(
            session,
            ctx,
            AuditAction.user_sessions_revoke,
            target_type="user",
            target_id=target.id,
            target_label=target.username,
            details={"revoked": revoked},
        )
    return revoked


async def delete_user(
    session: AsyncSession,
    store: BlobDeleter,
    actor: CurrentUser,
    user_id: int,
    ctx: AuditContext,
) -> int:
    """Delete a user with all their files (DELETE /admin/users/{id}). Returns the file count.

    Same order as ``files.delete_file``: first one transaction deletes the user row (whose
    foreign keys cascade to sessions, files, owned teams, memberships and links) and writes the
    audit entry, then the blobs are deleted. A blob that cannot be deleted is logged and left
    for orphan cleanup (D24); the user is gone either way. Audit rows stay.

    Raises:
        NotFound: the actor is not an admin, or the user does not exist.
        LastAdmin: the target is the actor or the last active admin.

    Side effects: deletes the user and then the blobs, writes ``user.delete`` with
    ``details.files_deleted``.
    """
    _require_admin(actor)

    async with session.begin():
        # The rules are checked under the admin locks, so another admin cannot act in between.
        active_admins = await _lock_active_admins(session)
        target = await _lock_target(session, user_id)
        if target.role == Role.admin:
            _check_last_admin(actor, target, active_admins)
        blob_names = list(
            await session.scalars(select(File.blob_name).where(File.owner_id == user_id))
        )
        await session.execute(delete(User).where(User.id == user_id))
        await audit.record(
            session,
            ctx,
            AuditAction.user_delete,
            target_type="user",
            target_id=user_id,
            target_label=target.username,
            details={"files_deleted": len(blob_names)},
        )

    # Sixteen at a time: one request per blob in a row would outlast the proxy timeout for a
    # user with many files. A failed delete only logs, so gather cannot raise.
    limit = asyncio.Semaphore(DELETE_CONCURRENCY)

    async def delete_blob(blob_name: str) -> None:
        async with limit:
            try:
                await store.delete(blob_name)
            except Exception as exc:
                logger.warning(
                    "Could not delete blob %s (%s); it is left for orphan cleanup",
                    blob_name,
                    type(exc).__name__,
                )

    await asyncio.gather(*(delete_blob(name) for name in blob_names))
    return len(blob_names)


# --- First admin ---------------------------------------------------------------------


async def ensure_initial_admin(
    session: AsyncSession, settings: Settings, *, now: datetime | None = None
) -> bool:
    """Create the first admin from ``INITIAL_ADMIN_USERNAME`` if that user does not exist.

    The account is ``active`` with role ``admin``. Safe to run on every startup and from several
    replicas at once: the unique username constraint decides, and the loser does nothing.

    Returns:
        True if this call created the account, False if it already existed.

    Side effects: inserts a user and writes an ``auth.register`` entry (actor ``system``).
    """
    now = now or datetime.now(UTC)
    username = settings.initial_admin_username

    # Cheap check first, so a normal restart does not pay for an Argon2 hash.
    async with session.begin():
        existing = await session.scalar(select(User.role).where(User.username == username))
        if existing is not None:
            if existing != Role.admin:
                logger.warning("INITIAL_ADMIN_USERNAME belongs to an account that is not an admin")
            return False

    password_hash = await hash_password(settings.initial_admin_password.get_secret_value())
    async with session.begin():
        # Another replica may have inserted the row since the check above: ON CONFLICT DO
        # NOTHING turns that race into "created is None" instead of an IntegrityError.
        created = await session.scalar(
            pg_insert(User)
            .values(
                username=username,
                password_hash=password_hash,
                role=Role.admin,
                status=UserStatus.active,
                approved_at=now,
            )
            .on_conflict_do_nothing(index_elements=["username"])
            .returning(User.id)
        )
        if created is not None:
            await audit.record(
                session,
                AuditContext.system(),
                AuditAction.auth_register,
                target_type="user",
                target_id=created,
                target_label=username,
                details={"initial_admin": True},
            )
    return created is not None
