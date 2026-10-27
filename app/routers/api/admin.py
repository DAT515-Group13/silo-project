"""Admin endpoints.

The role is read from the database on every request; non-admins get 404 on all of these.
The checks live in ``services/users.py`` and ``services/admin.py``; routers only parse, call
one service function and build the response.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from app.errors import NotFound
from app.models import AuditLog, Outcome, User, UserStatus
from app.permissions import is_admin
from app.ratelimit import limit
from app.routers.common import (
    MAX_ID,
    ApiUser,
    AuditCtx,
    DbSession,
    IntId,
    PageNumber,
    PageSize,
    Store,
    file_out,
)
from app.schemas.common import Page
from app.schemas.files import FileOut
from app.schemas.users import AdminUserOut, AdminUserPatchIn, AuditEntryOut, RejectIn
from app.services import admin, users
from app.services.admin import AuditFilters


async def require_admin_api_user(user: ApiUser) -> None:
    """Answer non-admins with 404 before any body or query validation runs.

    The services check the role as well. Without this, a non-admin sending an invalid body or
    filter would get a 422, which shows that the admin endpoint exists (section 6).
    """
    if not is_admin(user):
        raise NotFound


router = APIRouter(
    prefix="/api/v1/admin", tags=["admin"], dependencies=[Depends(require_admin_api_user)]
)


def admin_user_out(user: User, file_count: int | None = None) -> AdminUserOut:
    """Build the admin view of a user; never contains the password hash."""
    return AdminUserOut(
        id=user.id,
        username=user.username,
        role=user.role,
        status=user.status,
        used_bytes=user.used_bytes,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        file_count=file_count,
    )


def audit_entry_out(entry: AuditLog) -> AuditEntryOut:
    """Build one audit row of the response; ``ip`` comes from the database as an address."""
    return AuditEntryOut(
        id=entry.id,
        created_at=entry.created_at,
        actor_type=entry.actor_type,
        actor_id=entry.actor_id,
        actor_username=entry.actor_username,
        action=entry.action,
        outcome=entry.outcome,
        target_type=entry.target_type,
        target_id=entry.target_id,
        target_label=entry.target_label,
        ip=str(entry.ip) if entry.ip is not None else None,
        request_id=entry.request_id,
        details=entry.details,
    )


@router.get("/users", response_model=Page[AdminUserOut])
@limit("admin")
async def list_users(
    request: Request,
    user: ApiUser,
    session: DbSession,
    status: UserStatus | None = None,
    page: PageNumber = 1,
    size: PageSize = 20,
) -> Page[AdminUserOut]:
    """All users, newest first, optionally filtered by status, with their file counts."""
    items, total = await users.list_users(session, user, status=status, page=page, size=size)
    return Page[AdminUserOut](
        items=[admin_user_out(item.user, item.file_count) for item in items],
        total=total,
        page=page,
        size=size,
    )


@router.post("/users/{user_id}/approve", status_code=204)
@limit("admin")
async def approve_user(
    request: Request, user_id: IntId, user: ApiUser, ctx: AuditCtx, session: DbSession
) -> None:
    """Approve a pending account. Other states: 409 `invalid_user_state`."""
    await users.approve_user(session, user, user_id, ctx)


@router.post("/users/{user_id}/reject", status_code=204)
@limit("admin")
async def reject_user(
    request: Request,
    user_id: IntId,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
    body: RejectIn | None = None,
) -> None:
    """Reject a pending account with an optional reason. Other states: 409."""
    reason = body.reason if body is not None else None
    await users.reject_user(session, user, user_id, ctx, reason=reason)


@router.patch("/users/{user_id}", response_model=AdminUserOut)
@limit("admin")
async def update_user(
    request: Request,
    user_id: IntId,
    body: AdminUserPatchIn,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
) -> AdminUserOut:
    """Change role and/or status (`active` or `disabled`). Disabling revokes all sessions.

    Errors: 409 `last_admin` for yourself or the last active admin, 409 `invalid_user_state`
    for a status change of a pending or rejected account.
    """
    changed = await users.update_user(
        session, user, user_id, ctx, role=body.role, status=body.status
    )
    return admin_user_out(changed)


@router.post("/users/{user_id}/revoke-sessions", status_code=204)
@limit("admin")
async def revoke_user_sessions(
    request: Request, user_id: IntId, user: ApiUser, ctx: AuditCtx, session: DbSession
) -> None:
    """Log the user out on every device."""
    await users.revoke_user_sessions(session, user, user_id, ctx)


@router.delete("/users/{user_id}", status_code=204)
@limit("admin")
async def delete_user(
    request: Request,
    user_id: IntId,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
    store: Store,
) -> None:
    """Delete the user's blobs, then the user and everything they own.

    Errors: 409 `last_admin`; 503 `storage_unavailable` if a blob cannot be deleted.
    """
    await users.delete_user(session, store, user, user_id, ctx)


@router.get("/files", response_model=Page[FileOut])
@limit("admin")
async def list_all_files(
    request: Request,
    user: ApiUser,
    session: DbSession,
    page: PageNumber = 1,
    size: PageSize = 20,
) -> Page[FileOut]:
    """All files, metadata only (admins never download)."""
    items, total = await admin.list_all_files(session, user, page=page, size=size)
    return Page[FileOut](
        items=[file_out(item, user.id) for item in items], total=total, page=page, size=size
    )


@router.get("/audit", response_model=Page[AuditEntryOut])
@limit("admin")
async def list_audit(
    request: Request,
    user: ApiUser,
    session: DbSession,
    action: str | None = None,
    outcome: Outcome | None = None,
    actor_id: Annotated[int | None, Query(ge=1, le=MAX_ID)] = None,
    target_type: str | None = None,
    target_id: str | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    page: PageNumber = 1,
    size: PageSize = 20,
) -> Page[AuditEntryOut]:
    """The audit log, newest first. `from` is inclusive, `to` exclusive."""
    filters = AuditFilters(
        action=action,
        outcome=outcome,
        actor_id=actor_id,
        target_type=target_type,
        target_id=target_id,
        from_=from_,
        to=to,
    )
    entries, total = await admin.list_audit(session, user, filters, page=page, size=size)
    return Page[AuditEntryOut](
        items=[audit_entry_out(entry) for entry in entries], total=total, page=page, size=size
    )
