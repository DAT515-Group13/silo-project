"""Rate limit classes and the upload concurrency guard.

Limits: ``auth`` 10/min per IP, ``read`` 300/min per user, ``write`` 60/min per user, ``upload``
10/min per user, ``admin`` 120/min per user, ``public`` 30/min per IP. Uploads are also limited to
3 at a time per user.

The counters live in the memory of one process (no Redis). With N replicas the
effective limit is up to N times higher; this is an accepted limitation (open question Q6).
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
}

limiter = Limiter(key_func=_ip_key, storage_uri="memory://")


def limit(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that applies a rate limit class to a route function.

    The route function must have a parameter ``request: Request`` (slowapi needs it). Put the
    decorator below the ``@router.get(...)`` line. Exceeding the limit answers
    ``429 rate_limited`` with ``Retry-After``.
    """
    rate, key_func = LIMIT_CLASSES[name]
    return limiter.limit(rate, key_func=key_func)


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
