"""Auth and account endpoints.

Routers only parse the request, call one service function and build the response.
"""

import uuid

from fastapi import APIRouter, Request, Response

from app.ratelimit import limit
from app.routers.common import (
    ApiUser,
    AuditCtx,
    DbSession,
    SettingsDep,
    client_ip,
    request_id,
)
from app.schemas.auth import (
    LoginIn,
    MeOut,
    PasswordChangeIn,
    RefreshIn,
    RegisterIn,
    RegistrationAcceptedOut,
    SessionOut,
    TokenPairOut,
    UserBriefOut,
)
from app.services import auth, sessions, users
from app.services.sessions import IssuedTokens

router = APIRouter(prefix="/api/v1", tags=["auth"])


def _token_response(tokens: IssuedTokens) -> TokenPairOut:
    """Build the token pair response of example 9.1."""
    return TokenPairOut(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
        refresh_expires_in=tokens.refresh_expires_in,
        user=UserBriefOut(id=tokens.user_id, username=tokens.username, role=tokens.role),
    )


@router.post(
    "/auth/register",
    status_code=201,
    response_model=UserBriefOut | RegistrationAcceptedOut,
    responses={202: {"model": RegistrationAcceptedOut}},
)
@limit("auth")
async def register(
    body: RegisterIn,
    request: Request,
    response: Response,
    session: DbSession,
    settings: SettingsDep,
) -> UserBriefOut | RegistrationAcceptedOut:
    """Register an account (behavior per ``REGISTRATION_MODE``).

    `open`: 201 with the new user, or 409 `username_taken`. `approval`: always 202 with the same
    body, whether or not the username was taken. `closed`: 404.
    """
    user = await auth.register(
        session,
        settings,
        body.username,
        body.password,
        ip=client_ip(request),
        request_id=request_id(request),
    )
    if user is None:
        response.status_code = 202
        return RegistrationAcceptedOut()
    return UserBriefOut(id=user.id, username=user.username, role=user.role)


@router.post("/auth/login", response_model=TokenPairOut)
@limit("auth")
async def login(
    body: LoginIn, request: Request, session: DbSession, settings: SettingsDep
) -> TokenPairOut:
    """Log in with username and password and receive an access and a refresh token.

    Errors: 401 `invalid_credentials` (unknown user, wrong password, locked), 403
    `account_pending`, `account_rejected` or `account_disabled` (after a correct password).
    """
    tokens = await auth.login(
        session,
        settings,
        body.username,
        body.password,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_id=request_id(request),
    )
    return _token_response(tokens)


@router.post("/auth/refresh", response_model=TokenPairOut)
@limit("auth")
async def refresh(
    body: RefreshIn, request: Request, session: DbSession, settings: SettingsDep
) -> TokenPairOut:
    """Exchange a refresh token for a new token pair; the old refresh token becomes invalid.

    Errors: 401 `invalid_token`, 409 `refresh_in_progress` (parallel use of the same token).
    """
    tokens = await sessions.rotate_refresh(
        session,
        settings,
        body.refresh_token,
        ip=client_ip(request),
        request_id=request_id(request),
    )
    return _token_response(tokens)


@router.post("/auth/logout", status_code=204)
@limit("write")
async def logout(request: Request, user: ApiUser, ctx: AuditCtx, session: DbSession) -> None:
    """Revoke the current session; its access token stops working immediately."""
    await auth.logout(session, user, ctx)


@router.post("/auth/logout-all", status_code=204)
@limit("write")
async def logout_all(request: Request, user: ApiUser, ctx: AuditCtx, session: DbSession) -> None:
    """Revoke all sessions of the current user."""
    await auth.logout_all(session, user, ctx)


@router.get("/auth/sessions", response_model=list[SessionOut])
@limit("read")
async def list_sessions(request: Request, user: ApiUser, session: DbSession) -> list[SessionOut]:
    """List the current user's active sessions (example 9.6)."""
    rows = await sessions.list_active(session, user.id)
    return [
        SessionOut(
            id=row.id,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            ip=str(row.ip) if row.ip is not None else None,
            user_agent=row.user_agent,
            current=row.id == user.session_id,
        )
        for row in rows
    ]


@router.delete("/auth/sessions/{session_id}", status_code=204)
@limit("write")
async def revoke_session(
    request: Request, session_id: uuid.UUID, user: ApiUser, ctx: AuditCtx, session: DbSession
) -> None:
    """Revoke one of the current user's own sessions; others' or unknown sessions give 404."""
    await auth.revoke_own_session(session, user, session_id, ctx)


@router.get("/me", response_model=MeOut)
@limit("read")
async def me(request: Request, user: ApiUser, session: DbSession, settings: SettingsDep) -> MeOut:
    """Return the current user with storage usage and quota (example 9.2)."""
    account = await users.get_user(session, user.id)
    return MeOut(
        id=account.id,
        username=account.username,
        role=account.role,
        used_bytes=account.used_bytes,
        quota_bytes=settings.quota_for_role(account.role),
    )


@router.post("/me/password", status_code=204)
@limit("password", "password_ip")
async def change_password(
    body: PasswordChangeIn,
    request: Request,
    user: ApiUser,
    ctx: AuditCtx,
    session: DbSession,
    settings: SettingsDep,
) -> None:
    """Change the current user's password and sign out all other sessions.

    Errors: 422 `validation_error` for a wrong `current_password` or a weak `new_password`.
    """
    await auth.change_password(
        session, settings, user, ctx, body.current_password, body.new_password
    )
