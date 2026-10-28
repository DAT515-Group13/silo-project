"""Audit service."""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import AuditLog, Outcome
from app.services.audit import AuditAction, AuditContext, record, record_failure

# The exact list of audit actions.
SPEC_ACTIONS = {
    "auth.register", "auth.login", "auth.logout", "auth.logout_all", "auth.refresh",
    "auth.refresh_reuse", "auth.lockout", "auth.session_revoke", "auth.password_change",
    "file.upload",
    "file.download", "file.rename", "file.delete", "file.share", "file.unshare",
    "link.create", "link.revoke",
    "link.update", "link.download", "team.create", "team.delete",
    "team.member_add", "team.member_remove", "user.approve", "user.reject",
    "user.role_change", "user.deactivate", "user.activate", "user.sessions_revoke",
    "user.delete", "storage.orphan_cleanup",
}  # fmt: skip


def test_actions_match_the_spec_list() -> None:
    """AuditAction has exactly the actions, and each fits the column (50)."""
    values = {action.value for action in AuditAction}
    assert values == SPEC_ACTIONS
    assert all(len(value) <= 50 for value in values)


@pytest.mark.db
@pytest.mark.anyio
async def test_record_is_part_of_the_callers_transaction(
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """A recorded entry is committed with the transaction and carries all fields."""
    async with db_sessionmaker() as session, session.begin():
        await record(
            session,
            AuditContext.system(),
            AuditAction.storage_orphan_cleanup,
            details={"deleted": 2, "scanned": 5},
        )
        await record(
            session,
            AuditContext.anonymous(ip="203.0.113.9", request_id="req-2"),
            AuditAction.link_download,
            target_type="link",
            target_id=17,
            target_label="r" * 300,
        )
    async with db_sessionmaker() as session:
        rows = (await session.scalars(select(AuditLog).order_by(AuditLog.id))).all()
    assert [r.action for r in rows] == ["storage.orphan_cleanup", "link.download"]
    assert rows[0].details == {"deleted": 2, "scanned": 5}
    assert rows[0].outcome is Outcome.success
    # The ip column is INET, so the database returns an ipaddress object, not a string.
    assert (rows[1].target_id, rows[1].request_id, str(rows[1].ip)) == (
        "17",
        "req-2",
        "203.0.113.9",
    )
    assert len(rows[1].target_label or "") == 255


@pytest.mark.db
@pytest.mark.anyio
async def test_only_the_failure_entry_survives_a_rolled_back_transaction(
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """A success entry is rolled back with a failed action (the log never lies); a denied entry
    is written in its own session and stays."""
    ctx = AuditContext.anonymous(ip="203.0.113.7")
    with pytest.raises(RuntimeError):
        async with db_sessionmaker() as session, session.begin():
            await record(session, AuditContext.system(), AuditAction.user_delete)
            await record_failure(
                session,
                ctx,
                AuditAction.file_delete,
                outcome=Outcome.denied,
                target_type="file",
                target_id="abc",
            )
            raise RuntimeError("the action failed")
    async with db_sessionmaker() as session:
        rows = (await session.scalars(select(AuditLog))).all()
    assert len(rows) == 1
    assert (rows[0].action, rows[0].outcome, rows[0].target_id) == (
        "file.delete",
        Outcome.denied,
        "abc",
    )


@pytest.mark.anyio
async def test_record_failure_refuses_success() -> None:
    """Successes must go through record(), inside the action's transaction.

    The check comes before the session is used, so no database is needed.
    """
    with pytest.raises(ValueError, match="denied or failed"):
        await record_failure(
            None,  # type: ignore[arg-type]
            AuditContext.system(),
            AuditAction.user_delete,
            outcome=Outcome.success,
        )
