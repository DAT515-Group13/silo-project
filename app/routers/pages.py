"""HTML pages and form actions.

Implemented here: the start page, login, register, logout and the account page. Team pages are
in ``team_pages.py``, file pages in ``file_pages.py`` and admin pages in ``admin_pages.py``. Each
form action calls the same service function as its JSON counterpart. Every POST is protected by
``CsrfChecked`` (CSRF token and Origin check).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.errors import (
    AccountDisabled,
    AccountPending,
    AccountRejected,
    InvalidCredentials,
    NotFound,
    UsernameTaken,
    ValidationFailed,
)
from app.middleware import mark_logged_in, mark_logged_out, safe_next
from app.permissions import CurrentUser
from app.ratelimit import limit
from app.routers.common import (
    CsrfChecked,
    DbSession,
    OptionalPageUser,
    PageAuditCtx,
    PageUser,
    SettingsDep,
    client_ip,
    render_page,
    request_id,
    see_other,
    validation_messages,
)
from app.schemas.auth import (
    REGISTRATION_ACCEPTED_MESSAGE,
    LoginIn,
    PasswordChangeIn,
    RegisterIn,
)
from app.services import auth, sessions, users

router = APIRouter(include_in_schema=False)

LOGIN_FAILED_MESSAGE = "Invalid username or password."


# --- Start page and login --------------------------------------------------------------------


@router.get("/")
async def index(user: OptionalPageUser) -> Response:
    """Send logged-in visitors to their files and everybody else to the login page."""
    return see_other("/files" if user else "/login")


@router.get("/login")
async def login_page(
    request: Request,
    user: OptionalPageUser,
    settings: SettingsDep,
    next_url: Annotated[str | None, Query(alias="next")] = None,
    registered: bool = False,
) -> Response:
    """Show the login form. A visitor who is logged in already is sent on to ``next``."""
    target = safe_next(next_url)
    if user:
        return see_other(target)
    return render_page(
        request,
        settings,
        None,
        "login.html",
        {
            "next": target,
            "username": "",
            "error": None,
            "registered": registered,
            "registration_open": settings.registration_mode != "closed",
        },
    )


@router.post("/login", dependencies=[CsrfChecked])
@limit("auth")
async def login_submit(
    request: Request,
    session: DbSession,
    settings: SettingsDep,
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    next_url: Annotated[str, Form(alias="next")] = "",
) -> Response:
    """Log in: on success set the cookies and go to ``next``; on failure show the form again.

    Wrong credentials, a locked account and an unknown username all show the same message.
    A correct password for a pending, rejected or disabled account shows the account state.
    """
    target = safe_next(next_url)
    context = {
        "next": target,
        "username": username.strip().lower()[:32],
        "registered": False,
        "registration_open": settings.registration_mode != "closed",
    }
    try:
        # LoginIn caps the lengths, so a huge password is not hashed (it is simply wrong).
        form = LoginIn.model_validate({"username": username, "password": password})
        tokens = await auth.login(
            session,
            settings,
            form.username,
            form.password,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            request_id=request_id(request),
        )
    except ValidationError:
        return render_page(
            request,
            settings,
            None,
            "login.html",
            {**context, "error": LOGIN_FAILED_MESSAGE},
            status_code=401,
        )
    except (InvalidCredentials, AccountPending, AccountRejected, AccountDisabled) as exc:
        return render_page(
            request,
            settings,
            None,
            "login.html",
            {**context, "error": exc.detail},
            status_code=exc.status_code,
        )

    mark_logged_in(request, tokens)
    return see_other(target)


# --- Register --------------------------------------------------------------------------------


@router.get("/register")
async def register_page(
    request: Request, user: OptionalPageUser, settings: SettingsDep
) -> Response:
    """Show the registration form (404 in ``closed`` mode)."""
    if settings.registration_mode == "closed":
        raise NotFound
    if user:
        return see_other("/files")
    return render_page(
        request,
        settings,
        None,
        "register.html",
        {
            "username": "",
            "errors": [],
            "done": None,
            "password_min_length": settings.password_min_length,
        },
    )


@router.post("/register", dependencies=[CsrfChecked])
@limit("auth")
async def register_submit(
    request: Request,
    session: DbSession,
    settings: SettingsDep,
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
) -> Response:
    """Register an account.

    ``open`` mode: go to the login page. ``approval`` mode: always the same confirmation,
    whether or not the username was taken (no enumeration).
    """
    context = {
        "username": username.strip().lower()[:32],
        "done": None,
        "password_min_length": settings.password_min_length,
    }

    def again(errors: list[str], status_code: int) -> Response:
        return render_page(
            request,
            settings,
            None,
            "register.html",
            {**context, "errors": errors},
            status_code=status_code,
        )

    if settings.registration_mode == "closed":
        raise NotFound
    try:
        form = RegisterIn.model_validate({"username": username, "password": password})
        user = await auth.register(
            session,
            settings,
            form.username,
            form.password,
            ip=client_ip(request),
            request_id=request_id(request),
        )
    except ValidationError as exc:
        return again(validation_messages(exc), 422)
    except ValidationFailed as exc:
        return again([item["message"] for item in exc.errors], 422)
    except UsernameTaken:
        return again(["That username is already taken."], 409)

    if user is not None:  # open mode: the account is active
        return see_other("/login?registered=1")
    return render_page(
        request,
        settings,
        None,
        "register.html",
        {**context, "errors": [], "done": REGISTRATION_ACCEPTED_MESSAGE},
    )


# --- Logout and account ----------------------------------------------------------------------


@router.post("/logout", dependencies=[CsrfChecked])
@limit("write")
async def logout_submit(
    request: Request,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
) -> Response:
    """Revoke the current session, delete the cookies and go to the login page."""
    await auth.logout(session, user, ctx)
    mark_logged_out(request)
    return see_other("/login")


async def _account_response(
    request: Request,
    user: CurrentUser,
    session: AsyncSession,
    settings: Settings,
    *,
    errors: list[str] | None = None,
    password_changed: bool = False,
    status_code: int = 200,
) -> Response:
    """Render the account page (usage, sessions, password form)."""
    rows = await sessions.list_active(session, user.id)
    account = await users.get_user(session, user.id)
    return render_page(
        request,
        settings,
        user,
        "account.html",
        {
            "sessions": rows,
            "used_bytes": account.used_bytes,
            "quota_bytes": settings.quota_for_role(account.role),
            "errors": errors or [],
            "password_changed": password_changed,
            "password_min_length": settings.password_min_length,
        },
        status_code=status_code,
    )


@router.get("/account")
@limit("read")
async def account_page(
    request: Request,
    user: PageUser,
    session: DbSession,
    settings: SettingsDep,
    password_changed: bool = False,
) -> Response:
    """Show the user's storage usage, active sessions and the password form."""
    return await _account_response(
        request, user, session, settings, password_changed=password_changed
    )


@router.post("/account/password", dependencies=[CsrfChecked])
@limit("password", "password_ip")
async def change_password_submit(
    request: Request,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
    settings: SettingsDep,
    current_password: Annotated[str, Form()] = "",
    new_password: Annotated[str, Form()] = "",
) -> Response:
    """Change the password; other sessions end, this one stays. Errors show the page again."""
    try:
        form = PasswordChangeIn.model_validate(
            {"current_password": current_password, "new_password": new_password}
        )
        await auth.change_password(
            session, settings, user, ctx, form.current_password, form.new_password
        )
    except ValidationError as exc:
        errors = validation_messages(exc)
    except ValidationFailed as exc:
        errors = [item["message"] for item in exc.errors]
    else:
        return see_other("/account?password_changed=true")
    return await _account_response(request, user, session, settings, errors=errors, status_code=422)


@router.post("/account/logout-all", dependencies=[CsrfChecked])
@limit("write")
async def logout_all_submit(
    request: Request,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
) -> Response:
    """Revoke all sessions of the user, including this one."""
    await auth.logout_all(session, user, ctx)
    mark_logged_out(request)
    return see_other("/login")


@router.post("/account/sessions/{session_id}/revoke", dependencies=[CsrfChecked])
@limit("write")
async def revoke_session_submit(
    request: Request,
    session_id: uuid.UUID,
    user: PageUser,
    ctx: PageAuditCtx,
    session: DbSession,
) -> Response:
    """Revoke one of the user's own sessions; revoking the current one logs out."""
    await auth.revoke_own_session(session, user, session_id, ctx)
    if session_id != user.session_id:
        return see_other("/account")
    mark_logged_out(request)
    return see_other("/login")
