"""Rate limit classes and the upload concurrency guard.

Limits: ``auth`` 10/min per IP, ``read`` 300/min per user, ``write`` 60/min per user, ``upload``
10/min per user, ``admin`` 120/min per user, ``public`` 30/min per IP, ``password`` 5/min per
user and ``password_ip`` 20/min per IP (password change: it checks the current password, so
guessing must stay slow; both layers apply together). Uploads are also limited to 3 at a time
per user.

The counters live in the memory of one process (no Redis). With N replicas the
effective limit is up to N times higher; this is an accepted limitation (open question Q6).
Counters are per route, so the login page and ``/api/v1/auth/login`` each have their own 10/min.
Except the ``SHARED`` classes: one counter for all routes that use them (the password change
API and page).
Account lockout is what limits login guessing per account; password change has no lockout
(it would let a stolen token lock the owner out), so its limits above are the protection.
"""

from collections import defaultdict
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from app.errors import RateLimited

MAX_CONCURRENT_UPLOADS = 3
_FALLBACK_RETRY_AFTER = 60


def _ip_key(request: Request) -> str:
    """Rate limit key for anonymous endpoints: the client IP (already corrected by the proxy)."""
    return request.client.host if request.client else "unknown"


def _user_key(request: Request) -> str:
    """Rate limit key for authenticated endpoints: the user ID set by the auth dependency.

    The limit decorator runs after FastAPI resolved the dependencies, so the ID is known. If it
    is missing for any reason, fall back to the IP instead of sharing one bucket for everybody.
    """
    user_id = getattr(request.state, "user_id", None)
    return f"user:{user_id}" if user_id is not None else _ip_key(request)


# class name -> (limit, key function)
LIMIT_CLASSES: dict[str, tuple[str, Callable[[Request], str]]] = {
    "auth": ("10/minute", _ip_key),
    "read": ("300/minute", _user_key),
    "write": ("60/minute", _user_key),
    "upload": ("10/minute", _user_key),
    "admin": ("120/minute", _user_key),
    "public": ("30/minute", _ip_key),
    "password": ("5/minute", _user_key),
    "password_ip": ("20/minute", _ip_key),
}

# Classes with one counter for all their routes, so the JSON API and the HTML form of the same
# action cannot be used to double the allowed attempts.
SHARED = {"password", "password_ip"}

limiter = Limiter(key_func=_ip_key, storage_uri="memory://")


def limit(*names: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that applies one or more rate limit classes to a route function.

    The route function must have a parameter ``request: Request`` (slowapi needs it). Put the
    decorator below the ``@router.get(...)`` line. Exceeding a limit answers
    ``429 rate_limited`` with ``Retry-After``. With several classes all of them apply.
    """
    decorators = []
    for name in names:
        rate, key_func = LIMIT_CLASSES[name]
        if name in SHARED:
            decorators.append(limiter.shared_limit(rate, scope=name, key_func=key_func))
        else:
            decorators.append(limiter.limit(rate, key_func=key_func))

    def apply(func: Callable[..., Any]) -> Callable[..., Any]:
        for decorator in decorators:
            func = decorator(func)
        return func

    return apply


def reset_limits() -> None:
    """Forget all counters. Called when an app is created, so tests do not share counters."""
    limiter.reset()


async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Turn slowapi's exception into the standard error body with Retry-After.

    Retry-After is the length of the limit window, an upper bound for the wait.
    """
    window = getattr(getattr(exc, "limit", None), "limit", None)
    seconds = int(window.get_expiry()) if window is not None else _FALLBACK_RETRY_AFTER
    error = RateLimited(retry_after=seconds)
    return JSONResponse(
        {"detail": error.detail, "code": error.code},
        status_code=error.status_code,
        headers={"Retry-After": str(seconds)},
    )


class ConcurrencyGuard:
    """Allows at most ``limit`` simultaneous holders per key (here: uploads per user)."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._active: defaultdict[int, int] = defaultdict(int)

    @asynccontextmanager
    async def slot(self, key: int) -> AsyncIterator[None]:
        """Hold a slot for the duration of the ``async with`` block.

        Raises:
            RateLimited: if ``key`` already holds the maximum number of slots.
        """
        # No await between check and increment, so this is atomic within the event loop.
        if self._active[key] >= self._limit:
            raise RateLimited(retry_after=_FALLBACK_RETRY_AFTER)
        self._active[key] += 1
        try:
            yield
        finally:
            self._active[key] -= 1
            if self._active[key] == 0:
                del self._active[key]  # do not keep an entry for every user ever seen


_upload_guard = ConcurrencyGuard(MAX_CONCURRENT_UPLOADS)


def upload_slot(user_id: int) -> AbstractAsyncContextManager[None]:
    """Hold one of the user's 3 concurrent upload slots: ``async with upload_slot(user.id):``."""
    return _upload_guard.slot(user_id)
