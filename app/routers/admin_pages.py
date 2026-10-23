"""Admin pages and their form actions.

Each page and form action calls the same service function as its JSON counterpart in
``routers/api/admin.py``; the services answer non-admins with ``NotFound``, which becomes the
HTML 404 page. Every POST is protected by ``CsrfChecked``. Domain errors (409 ``last_admin``,
409 ``invalid_user_state``, 503 ``storage_unavailable``) become the HTML error page.
"""

from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request, Response
from pydantic import ValidationError

from app.errors import NotFound, ValidationFailed
from app.models import Outcome, Role, UserStatus
from app.permissions import CurrentUser, is_admin
from app.ratelimit import limit
from app.routers.common import (
    CsrfChecked,
    DbSession,
    PageAuditCtx,
    PageNumber,
    PageUser,
    SettingsDep,
    Store,
    file_out,
    render_page,
    see_other,
    validation_messages,
)
from app.schemas.users import AdminUserPatchIn, RejectIn
from app.services import admin, users
from app.services.admin import AuditFilters

router = APIRouter(include_in_schema=False)

PER_PAGE = 25


async def require_admin_page_user(user: PageUser) -> CurrentUser:
    """The logged-in page user, if they are an admin; everybody else gets the 404 page.

    The services check this as well. Doing it here first means a non-admin never sees a
    validation error from an admin form, which would reveal that the page exists.
    """
    if not is_admin(user):
        raise NotFound
    return user


AdminUser = Annotated[CurrentUser, Depends(require_admin_page_user)]

# Route dependencies of every admin POST, resolved in this order: the admin check first, so a
# non-admin gets the 404 page even without a CSRF token (a 403 would reveal the action exists).
# FastAPI caches the admin check, so the route's ``AdminUser`` parameter reuses its result.
ADMIN_POST = [Depends(require_admin_page_user), CsrfChecked]


def _pages(total: int) -> int:
    """Number of pages for ``total`` rows (at least 1, so "page 1 of 1" for an empty list)."""
    return max(1, -(-total // PER_PAGE))


def _invalid(field: str, message: str) -> ValidationFailed:
    """A 422 for a page form, rendered as the error page with ``message``."""
    return ValidationFailed([{"field": field, "message": message}], detail=message)


# --- Users ---------------------------------------------------------------------------------------


@router.get("/admin")
@limit("admin")
async def users_page(
    request: Request,
    user: AdminUser,
    session: DbSession,
    settings: SettingsDep,
    status: str = "",
    page: PageNumber = 1,
) -> Response:
    """All users with their state, file count and the admin actions (admins only)."""
    try:
        status_filter = UserStatus(status) if status else None
    except ValueError:
        status_filter = None  # an unknown filter value shows everybody
    items, total = await users.list_users(
        session, user, status=status_filter, page=page, size=PER_PAGE
    )
    return render_page(
        request,
        settings,
        user,
        "admin_users.html",
        {
            "items": items,
            "status": status_filter.value if status_filter else "",
            "statuses": [s.value for s in UserStatus],
            "roles": [r.value for r in Role],
            "page": page,
            "pages": _pages(total),
            "total": total,
        },
    )


@router.post("/admin/users/{user_id}", dependencies=ADMIN_POST)
@limit("admin")
async def update_user_submit(
    request: Request,
    user_id: int,
    user: AdminUser,
    ctx: PageAuditCtx,
    session: DbSession,
    role: Annotated[str, Form()] = "",
    status: Annotated[str, Form()] = "",
) -> Response:
    """Change role and/or status (``active`` or ``disabled``); empty fields stay unchanged."""
    try:
        form = AdminUserPatchIn.model_validate({"role": role or None, "status": status or None})
    except ValidationError as exc:
        raise _invalid("role", " ".join(validation_messages(exc))) from exc
    await users.update_user(session, user, user_id, ctx, role=form.role, status=form.status)
    return see_other("/admin")


@router.post("/admin/users/{user_id}/approve", dependencies=ADMIN_POST)
@limit("admin")
async def approve_user_submit(
    request: Request, user_id: int, user: AdminUser, ctx: PageAuditCtx, session: DbSession
) -> Response:
    """Approve a pending account."""
    await users.approve_user(session, user, user_id, ctx)
    return see_other("/admin?status=pending")


@router.post("/admin/users/{user_id}/reject", dependencies=ADMIN_POST)
@limit("admin")
async def reject_user_submit(
    request: Request,
    user_id: int,
    user: AdminUser,
    ctx: PageAuditCtx,
    session: DbSession,
    reason: Annotated[str, Form()] = "",
) -> Response:
    """Reject a pending account with an optional reason (kept in the audit log)."""
    try:
        form = RejectIn.model_validate({"reason": reason or None})
    except ValidationError as exc:
        raise _invalid("reason", " ".join(validation_messages(exc))) from exc
    await users.reject_user(session, user, user_id, ctx, reason=form.reason or None)
    return see_other("/admin?status=pending")


@router.post("/admin/users/{user_id}/revoke-sessions", dependencies=ADMIN_POST)
@limit("admin")
async def revoke_sessions_submit(
    request: Request, user_id: int, user: AdminUser, ctx: PageAuditCtx, session: DbSession
) -> Response:
    """Log the user out on every device."""
    await users.revoke_user_sessions(session, user, user_id, ctx)
    return see_other("/admin")


@router.post("/admin/users/{user_id}/delete", dependencies=ADMIN_POST)
@limit("admin")
async def delete_user_submit(
    request: Request,
    user_id: int,
    user: AdminUser,
    ctx: PageAuditCtx,
    session: DbSession,
    store: Store,
    confirm: Annotated[str, Form()] = "",
) -> Response:
    """Delete a user and all their files, after the confirmation box was ticked."""
    # The page shows the file count next to the box; deleting is final, so it must be ticked.
    if confirm != "yes":
        raise _invalid("confirm", "Tick the confirmation box to delete the user and their files.")
    await users.delete_user(session, store, user, user_id, ctx)
    return see_other("/admin")


# --- Files and audit -----------------------------------------------------------------------------


@router.get("/admin/files")
@limit("admin")
async def files_page(
    request: Request,
    user: AdminUser,
    session: DbSession,
    settings: SettingsDep,
    page: PageNumber = 1,
) -> Response:
    """All files as metadata only; admins never download other users' files."""
    items, total = await admin.list_all_files(session, user, page=page, size=PER_PAGE)
    return render_page(
        request,
        settings,
        user,
        "admin_files.html",
        {
            "files": [file_out(item, user.id) for item in items],
            "page": page,
            "pages": _pages(total),
            "total": total,
        },
    )


def _parse_time(name: str, value: str) -> datetime | None:
    """Parse a ``datetime-local`` form value; times without a zone are taken as UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise _invalid(name, f"'{name}' is not a valid date and time.") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@router.get("/admin/audit")
@limit("admin")
async def audit_page(
    request: Request,
    user: AdminUser,
    session: DbSession,
    settings: SettingsDep,
    action: str = "",
    outcome: str = "",
    actor_id: str = "",
    target_type: str = "",
    target_id: str = "",
    from_: Annotated[str, Query(alias="from")] = "",
    to: str = "",
    page: PageNumber = 1,
) -> Response:
    """The audit log with a filter form, newest first (admins only)."""
    try:
        outcome_filter = Outcome(outcome) if outcome else None
        actor_filter = int(actor_id) if actor_id else None
    except ValueError as exc:
        raise _invalid("filter", "A filter value is not valid.") from exc
    filters = AuditFilters(
        action=action.strip() or None,
        outcome=outcome_filter,
        actor_id=actor_filter,
        target_type=target_type.strip() or None,
        target_id=target_id.strip() or None,
        from_=_parse_time("from", from_),
        to=_parse_time("to", to),
    )
    entries, total = await admin.list_audit(session, user, filters, page=page, size=PER_PAGE)

    # The pagination links repeat the filters; urlencode escapes them.
    form_values = {
        "action": action,
        "outcome": outcome,
        "actor_id": actor_id,
        "target_type": target_type,
        "target_id": target_id,
        "from": from_,
        "to": to,
    }
    return render_page(
        request,
        settings,
        user,
        "admin_audit.html",
        {
            "entries": entries,
            "filters": form_values,
            "filter_query": urlencode({k: v for k, v in form_values.items() if v}),
            "outcomes": [o.value for o in Outcome],
            "page": page,
            "pages": _pages(total),
            "total": total,
        },
    )
