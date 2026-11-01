"""Domain errors and how the exception handlers render them."""

from app import errors
from app.errors import SiloError

# Status code and error code of every domain error.
EXPECTED = {
    errors.InvalidCredentials: (401, "invalid_credentials"),
    errors.InvalidToken: (401, "invalid_token"),
    errors.AccountPending: (403, "account_pending"),
    errors.AccountRejected: (403, "account_rejected"),
    errors.AccountDisabled: (403, "account_disabled"),
    errors.UsernameTaken: (409, "username_taken"),
    errors.QuotaExceeded: (413, "quota_exceeded"),
    errors.StorageFull: (507, "storage_full"),
    errors.FileTooLarge: (413, "file_too_large"),
    errors.NotFound: (404, "not_found"),
    errors.LastAdmin: (409, "last_admin"),
    errors.OwnerCannotLeave: (409, "owner_cannot_leave"),
    errors.LinkLimit: (409, "link_limit"),
    errors.RefreshInProgress: (409, "refresh_in_progress"),
    errors.CsrfFailed: (403, "csrf_failed"),
    errors.RateLimited: (429, "rate_limited"),
    errors.ValidationFailed: (422, "validation_error"),
    errors.StorageUnavailable: (503, "storage_unavailable"),
    errors.InvalidUserState: (409, "invalid_user_state"),
    errors.TeamNameTaken: (409, "team_name_taken"),
    errors.RoleRequired: (403, "role_required"),
}


def test_every_error_has_its_status_and_code() -> None:
    """Every domain error has the specified status and code; no class is missing or extra."""
    domain = [
        c
        for c in vars(errors).values()
        if isinstance(c, type) and issubclass(c, SiloError) and c is not SiloError
    ]
    assert {c: (c.status_code, c.code) for c in domain} == EXPECTED
    codes = [c.code for c in domain]
    assert len(codes) == len(set(codes)), "two classes share a code"
