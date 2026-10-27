"""Audit log writing.

``record`` adds an entry inside the caller's transaction, so it is committed or rolled back
together with the action it describes. ``record_failure`` writes in a separate session, so entries
for denied or failed actions survive the rollback of the action itself.
"""

import enum
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ActorType, AuditLog, Outcome


class AuditAction(enum.StrEnum):
    """Every action that is written to the audit log."""

    auth_register = "auth.register"
    auth_login = "auth.login"
    auth_logout = "auth.logout"
    auth_logout_all = "auth.logout_all"
    auth_refresh = "auth.refresh"
    auth_refresh_reuse = "auth.refresh_reuse"
    auth_lockout = "auth.lockout"
    auth_session_revoke = "auth.session_revoke"
    auth_password_change = "auth.password_change"  # noqa: S105 - action name
    file_upload = "file.upload"
    file_download = "file.download"
    file_rename = "file.rename"
    file_delete = "file.delete"
    file_share = "file.share"
    file_unshare = "file.unshare"
    link_create = "link.create"
    link_revoke = "link.revoke"
    link_download = "link.download"
    team_create = "team.create"
    team_delete = "team.delete"
    team_member_add = "team.member_add"
    team_member_remove = "team.member_remove"
    user_approve = "user.approve"
    user_reject = "user.reject"
    user_role_change = "user.role_change"
    user_deactivate = "user.deactivate"
    user_activate = "user.activate"
    user_sessions_revoke = "user.sessions_revoke"
    user_delete = "user.delete"
    storage_orphan_cleanup = "storage.orphan_cleanup"


@dataclass(frozen=True)
class AuditContext:
    """Who acts, and from where. Built once per request and passed to the services.

    ``actor_username`` is a snapshot: the audit row stays readable after the user is deleted.
    """

    actor_type: ActorType
    actor_id: int | None = None
    actor_username: str | None = None
    ip: str | None = None
    request_id: str | None = None

    @classmethod
    def for_user(
        cls, user_id: int, username: str, *, ip: str | None = None, request_id: str | None = None
    ) -> "AuditContext":
        """Context of a logged-in user."""
        return cls(ActorType.user, user_id, username, ip, request_id)

    @classmethod
    def anonymous(cls, *, ip: str | None = None, request_id: str | None = None) -> "AuditContext":
        """Context of a request without login (public links, failed logins)."""
        return cls(ActorType.anonymous, None, None, ip, request_id)

    @classmethod
    def system(cls, *, request_id: str | None = None) -> "AuditContext":
        """Context of the app itself (first admin creation, orphan cleanup)."""
        return cls(ActorType.system, None, None, None, request_id)


def _entry(
    ctx: AuditContext,
    action: AuditAction,
    outcome: Outcome,
    target_type: str | None,
    target_id: str | int | None,
    target_label: str | None,
    details: dict[str, Any] | None,
) -> AuditLog:
    """Build the table row. Labels are cut to the column size instead of failing the action."""
    return AuditLog(
        actor_type=ctx.actor_type,
        actor_id=ctx.actor_id,
        actor_username=ctx.actor_username,
        action=action.value,
        outcome=outcome,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        target_label=target_label[:255] if target_label else None,
        ip=ctx.ip,
        request_id=ctx.request_id,
        details=details,
    )


async def record(
    session: AsyncSession,
    ctx: AuditContext,
    action: AuditAction,
    *,
    outcome: Outcome = Outcome.success,
    target_type: str | None = None,
    target_id: str | int | None = None,
    target_label: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Add an audit entry to the caller's transaction.

    The entry is written when that transaction commits and disappears if it rolls back. Use it
    for successful actions, so the log never claims something that did not happen. It does not
    commit.
    """
    session.add(_entry(ctx, action, outcome, target_type, target_id, target_label, details))
    # flush: a bad value (for example a too long action) fails here, not at commit time.
    await session.flush()


async def record_failure(
    session: AsyncSession,
    ctx: AuditContext,
    action: AuditAction,
    *,
    outcome: Outcome,
    target_type: str | None = None,
    target_id: str | int | None = None,
    target_label: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Write an entry for a denied or failed action in its own session and commit it at once.

    The rows must survive the rollback of the failed action, so they cannot share
    its transaction. ``session`` is only used to find the database: it is not touched, and it
    may be in the middle of a transaction that is about to roll back.

    Raises:
        ValueError: if ``outcome`` is ``success`` (successes belong in the action's transaction).
    """
    if outcome is Outcome.success:
        raise ValueError("record_failure is only for denied or failed outcomes")
    async with AsyncSession(bind=session.bind, expire_on_commit=False) as own, own.begin():
        own.add(_entry(ctx, action, outcome, target_type, target_id, target_label, details))
