"""Read-only admin views: all files, the audit log and the total storage.

User management lives in ``services/users.py``. Both listings are for admins only; everybody
else gets ``NotFound``. Admins see file metadata only, never file contents.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.errors import NotFound
from app.models import AuditLog, File, Outcome, User
from app.permissions import CurrentUser, is_admin
from app.services import users
from app.services.pagination import fetch_page
from app.services.teams import FileItem


@dataclass(frozen=True)
class AuditFilters:
    """Filters of ``GET /admin/audit``: ``None`` or ``""`` is "no filter", ``to`` is exclusive."""

    action: str | None = None
    outcome: Outcome | None = None
    actor_id: int | None = None
    target_type: str | None = None
    target_id: str | None = None
    from_: datetime | None = None
    to: datetime | None = None


def _require_admin(actor: CurrentUser) -> None:
    """Permission check: non-admins get 404, not 403."""
    if not is_admin(actor):
        raise NotFound


async def list_all_files(
    session: AsyncSession, actor: CurrentUser, *, page: int, size: int
) -> tuple[list[FileItem], int]:
    """Every file of every user, newest first, metadata only (GET /admin/files).

    Raises:
        NotFound: the actor is not an admin.
    """
    _require_admin(actor)
    async with session.begin():
        statement = (
            select(File, User.username)
            .join(User, User.id == File.owner_id)
            .order_by(File.created_at.desc(), File.id)
        )
        rows, total = await fetch_page(session, statement, page=page, size=size)
    return [FileItem(file=row[0], owner_username=row[1]) for row in rows], total


async def list_audit(
    session: AsyncSession, actor: CurrentUser, filters: AuditFilters, *, page: int, size: int
) -> tuple[list[AuditLog], int]:
    """Audit entries, newest first, with optional filters (GET /admin/audit).

    The order matches the ``created_at DESC`` indexes.

    Raises:
        NotFound: the actor is not an admin.
    """
    _require_admin(actor)
    statement = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    conditions = {
        AuditLog.action: filters.action,
        AuditLog.outcome: filters.outcome,
        AuditLog.actor_id: filters.actor_id,
        AuditLog.target_type: filters.target_type,
        AuditLog.target_id: filters.target_id,
    }
    for column, value in conditions.items():
        # An empty form field means "no filter", not "equal to the empty string".
        if value is not None and value != "":
            statement = statement.where(column == value)
    if filters.from_ is not None:
        statement = statement.where(AuditLog.created_at >= filters.from_)
    if filters.to is not None:
        statement = statement.where(AuditLog.created_at < filters.to)

    async with session.begin():
        rows, total = await fetch_page(session, statement, page=page, size=size)
    return [row[0] for row in rows], total


async def storage_totals(
    session: AsyncSession, actor: CurrentUser, settings: Settings
) -> tuple[int, int | None]:
    """Return ``(bytes stored by all users, STORAGE_TOTAL_MAX_BYTES or None)`` for /admin.

    One aggregate number: the admin sees no per-file or per-user data through it.

    Raises:
        NotFound: the actor is not an admin.
    """
    _require_admin(actor)
    async with session.begin():
        used = await users.total_used_bytes(session)
    return used, settings.global_cap()
