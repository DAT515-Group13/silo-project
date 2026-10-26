"""Rate limit classes and the upload concurrency guard."""

import asyncio
import itertools

import httpx
import pytest
from fastapi import FastAPI, Request

from app import ratelimit
from app.errors import RateLimited
from app.main import create_app
from app.ratelimit import ConcurrencyGuard, limit
from tests.conftest import make_settings
from tests.fakes import InMemoryBlobStore

pytestmark = pytest.mark.anyio


_route_numbers = itertools.count()


def add_limited_route(app: FastAPI, name: str = "auth") -> None:
    """Add a route with a rate limit class to the app, without any database use."""

    async def _limited(request: Request) -> dict[str, bool]:
        return {"ok": True}

    # slowapi registers limits under the function's module and name. Decorating several
    # functions with the same name would stack their limits on one bucket, which only happens
    # in tests that build many apps, so every route gets its own name.
    _limited.__name__ = f"limited_{next(_route_numbers)}"
    app.get("/api/v1/_limited")(limit(name)(_limited))


def client_from(app: FastAPI, ip: str = "203.0.113.5") -> httpx.AsyncClient:
    """An ASGI client that the app sees as coming from ``ip``."""
    transport = httpx.ASGITransport(app=app, client=(ip, 5000))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def test_classes_match_the_spec() -> None:
    """The limits and what they are keyed on."""
    limits = {name: rate for name, (rate, _) in ratelimit.LIMIT_CLASSES.items()}
    assert limits == {
        "auth": "10/minute",
        "read": "300/minute",
        "write": "60/minute",
        "upload": "10/minute",
        "admin": "120/minute",
        "public": "30/minute",
    }
    keys = {name: key.__name__ for name, (_, key) in ratelimit.LIMIT_CLASSES.items()}
    assert keys["auth"] == keys["public"] == "_ip_key"
    assert {keys[n] for n in ("read", "write", "upload", "admin")} == {"_user_key"}


def test_user_key_uses_the_user_id_or_falls_back_to_the_ip() -> None:
    """Per-user limits key on the authenticated user; without one, on the IP."""

    def request(state: dict) -> Request:
        return Request(
            {"type": "http", "headers": [], "client": ("198.51.100.1", 1), "state": state}
        )

    assert ratelimit._user_key(request({"user_id": 7})) == "user:7"
    assert ratelimit._user_key(request({})) == "198.51.100.1"


async def test_eleventh_request_in_a_minute_is_429_per_ip(app: FastAPI) -> None:
    """The auth class allows 10 requests per minute and IP; the 11th is 429. Other IPs are free."""
    add_limited_route(app, "auth")
    async with client_from(app, "203.0.113.5") as busy, client_from(app, "203.0.113.6") as other:
        for _ in range(10):
            assert (await busy.get("/api/v1/_limited")).status_code == 200
        response = await busy.get("/api/v1/_limited")
        assert response.status_code == 429
        assert response.json() == {"detail": "Too many requests.", "code": "rate_limited"}
        assert response.headers["retry-after"] == "60"
        assert (await other.get("/api/v1/_limited")).status_code == 200


async def test_a_new_app_starts_with_empty_counters() -> None:
    """create_app resets the counters, so tests (and restarts) never inherit them.

    Both apps use the same route function, hence the same bucket: only the reset can make the
    second app start from zero.
    """

    async def _limited(request: Request) -> dict[str, bool]:
        return {"ok": True}

    route = limit("auth")(_limited)
    for _ in range(2):
        app = create_app(make_settings(), InMemoryBlobStore(), initial_admin=False)
        app.get("/api/v1/_limited")(route)
        async with client_from(app) as client:
            for _ in range(10):
                assert (await client.get("/api/v1/_limited")).status_code == 200
            assert (await client.get("/api/v1/_limited")).status_code == 429


def test_both_login_routes_use_the_auth_limit() -> None:
    """The login page and the login API are limited to 10 a minute per IP (class `auth`).

    The 429 itself is tested with a stand-in route above; this checks that the real routes carry
    the limit. It reads slowapi's registry, which is pinned in pyproject.toml.
    """
    registered = ratelimit.limiter._route_limits
    for name in ("app.routers.api.auth.login", "app.routers.pages.login_submit"):
        assert [str(limit.limit) for limit in registered[name]] == ["10 per 1 minute"], name


async def test_concurrency_guard_allows_three_at_a_time() -> None:
    """Of 5 simultaneous uploads of one user, 3 get a slot and 2 are refused."""
    guard = ConcurrencyGuard(3)
    release = asyncio.Event()

    async def upload() -> str:
        try:
            async with guard.slot(1):
                await release.wait()
                return "ok"
        except RateLimited:
            return "refused"

    tasks = [asyncio.create_task(upload()) for _ in range(5)]
    await asyncio.sleep(0.05)  # let every task reach the guard while the slots are held
    release.set()
    results = await asyncio.gather(*tasks)
    assert sorted(results) == ["ok", "ok", "ok", "refused", "refused"]


async def test_concurrency_guard_is_per_user_and_releases_slots() -> None:
    """Another user is independent; slots come back after use, also after an error."""
    guard = ConcurrencyGuard(1)
    async with guard.slot(1):
        async with guard.slot(2):
            with pytest.raises(RateLimited):
                async with guard.slot(1):
                    pytest.fail("the second slot of user 1 must be refused")
    with pytest.raises(RuntimeError):
        async with guard.slot(1):
            raise RuntimeError("upload failed")
    async with guard.slot(1):  # the failed upload released its slot
        pass
    assert not guard._active  # nothing is kept for users without uploads
