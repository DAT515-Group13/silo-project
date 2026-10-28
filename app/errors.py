"""Domain exceptions. Each carries an HTTP status and a machine-readable code.

This module must not import anything from FastAPI or Starlette: services do not
know about HTTP. One exception handler in ``main.py`` turns these into responses.
The codes are the list in the specification.
"""


class SiloError(Exception):
    """Base class of all domain errors.

    Subclasses set ``status_code``, ``code`` and a default ``detail``. A caller may pass a
    different ``detail``, but never one that depends on why authentication failed (no enumeration).
    """

    status_code: int = 500
    code: str = "internal_error"
    detail: str = "Internal server error."

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail or type(self).detail
        super().__init__(self.detail)


class InvalidCredentials(SiloError):
    """Wrong username or password, an unknown username or a locked account (same answer)."""

    status_code = 401
    code = "invalid_credentials"
    detail = "Invalid username or password."


class InvalidToken(SiloError):
    """Missing, malformed, expired or revoked token. One message for every cause."""

    status_code = 401
    code = "invalid_token"
    detail = "Invalid or expired token."


class AccountPending(SiloError):
    """Correct password, but the account is waiting for admin approval."""

    status_code = 403
    code = "account_pending"
    detail = "Account is pending approval."


class AccountRejected(SiloError):
    """Correct password, but an admin rejected the account."""

    status_code = 403
    code = "account_rejected"
    detail = "Account was rejected."


class AccountDisabled(SiloError):
    """Correct password, but the account is disabled."""

    status_code = 403
    code = "account_disabled"
    detail = "Account is disabled."


class UsernameTaken(SiloError):
    """Registration in ``open`` mode with a username that already exists."""

    status_code = 409
    code = "username_taken"
    detail = "Username is already taken."


class TeamNameTaken(SiloError):
    """The owner already has a team with this name (names are unique per owner, D18)."""

    status_code = 409
    code = "team_name_taken"
    detail = "You already have a team with this name."


class InvalidUserState(SiloError):
    """Approve or reject of a user who is not ``pending`` (D18)."""

    status_code = 409
    code = "invalid_user_state"
    detail = "The account is not waiting for approval."


class RoleRequired(SiloError):
    """The caller's role may not do this, for example a plain ``user`` creating a team (D19).

    Used only where the request is about the caller's role, not about a hidden object: missing
    access to an object is always ``NotFound``.
    """

    status_code = 403
    code = "role_required"
    detail = "Your role does not allow this action."


class QuotaExceeded(SiloError):
    """The upload does not fit into the user's remaining storage quota."""

    status_code = 413
    code = "quota_exceeded"
    detail = "Storage quota exceeded."


class StorageFull(QuotaExceeded):
    """The upload does not fit into the total storage of the service (STORAGE_TOTAL_MAX_BYTES).

    A subclass of ``QuotaExceeded`` so the upload routes handle both the same way (drain the
    body, show the message). The service, not the user, is out of room, hence 507.
    """

    status_code = 507  # RFC 4918 Insufficient Storage; 413 is kept for the user's own quota
    code = "storage_full"
    detail = "The service storage is full. Contact an admin."


class FileTooLarge(SiloError):
    """The upload is larger than ``MAX_FILE_SIZE_BYTES``."""

    status_code = 413
    code = "file_too_large"
    detail = "File is too large."


class NotFound(SiloError):
    """The object does not exist or the caller may not know about it (always 404)."""

    status_code = 404
    code = "not_found"
    detail = "Not found."


class LastAdmin(SiloError):
    """Delete, disable or demote of the last active admin, or an admin acting on themselves."""

    status_code = 409
    code = "last_admin"
    detail = "Operation not allowed on the last active admin or on yourself."


class OwnerCannotLeave(SiloError):
    """The owner of a team tried to leave it; they must delete the team instead."""

    status_code = 409
    code = "owner_cannot_leave"
    detail = "The team owner cannot leave the team."


class LinkLimit(SiloError):
    """The file already has the maximum number of active public links."""

    status_code = 409
    code = "link_limit"
    detail = "Too many active links for this file."


class RefreshInProgress(SiloError):
    """A refresh token was reused within the grace window of its rotation."""

    status_code = 409
    code = "refresh_in_progress"
    detail = "Token refresh already in progress."


class CsrfFailed(SiloError):
    """CSRF token, Origin or Sec-Fetch-Site check failed on a page POST."""

    status_code = 403
    code = "csrf_failed"
    detail = "CSRF validation failed."


class RateLimited(SiloError):
    """A rate limit class was exceeded; ``retry_after`` (seconds) becomes ``Retry-After``."""

    status_code = 429
    code = "rate_limited"
    detail = "Too many requests."

    def __init__(self, detail: str | None = None, retry_after: int | None = None) -> None:
        super().__init__(detail)
        self.retry_after = retry_after


class ValidationFailed(SiloError):
    """A business-rule validation failed; ``errors`` lists ``{"field", "message"}`` entries."""

    status_code = 422
    code = "validation_error"
    detail = "Validation error."

    def __init__(self, errors: list[dict[str, str]], detail: str | None = None) -> None:
        super().__init__(detail)
        self.errors = errors


class StorageUnavailable(SiloError):
    """Blob storage failed or is unreachable. Metadata endpoints keep working."""

    status_code = 503
    code = "storage_unavailable"
    detail = "Storage is temporarily unavailable."
