"""No password, token or connection string reaches the logs.

These requests all fail before the database, so they run everywhere. The link token and the
audit log are covered by the ``db`` test in ``test_links.py``.
"""

import logging
import uuid

import httpx
import pytest

from app.config import Settings
from tests.conftest import ORIGIN, bearer, make_settings, token_for, token_of

pytestmark = pytest.mark.anyio

SECRET_PASSWORD = "Sup3r-secret-password-value"


async def test_failed_requests_do_not_log_credentials(
    client: httpx.AsyncClient, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """Rejected logins, registrations and tokens leave neither the password nor the token."""
    caplog.set_level(logging.DEBUG)
    forged = token_for(settings, 1, uuid.uuid4(), secret="x" * 40)

    responses = [
        await client.post(
            "/api/v1/auth/login", json={"username": "x" * 80, "password": SECRET_PASSWORD}
        ),
        await client.post(
            "/api/v1/auth/register", json={"username": "x", "password": SECRET_PASSWORD}
        ),
        await client.post("/api/v1/auth/refresh", json={"refresh_token": "r" * 200}),
        await client.get("/api/v1/me", headers=bearer(forged)),
        await client.get("/api/v1/me", headers={"Authorization": f"Bearer {SECRET_PASSWORD}"}),
    ]
    page = await client.get("/login")
    responses.append(
        await client.post(
            "/login",
            data={
                "csrf_token": token_of(page),
                "username": "x" * 80,
                "password": SECRET_PASSWORD,
            },
            headers=ORIGIN,
        )
    )

    # Every request really failed (a crash would be a 500 and would not prove anything).
    assert page.status_code == 200
    assert [r.status_code for r in responses] == [422, 422, 422, 401, 401, 401]
    assert caplog.records  # something was captured, so the checks below can fail
    assert SECRET_PASSWORD not in caplog.text
    assert forged not in caplog.text
    assert "r" * 200 not in caplog.text


def test_settings_never_print_secrets() -> None:
    """repr() and str() of the settings hide every secret (a stray log of the object is safe)."""
    settings: Settings = make_settings()
    text = f"{settings!r} {settings}"
    for secret in (
        settings.jwt_secret,
        settings.csrf_secret,
        settings.database_url,
        settings.azure_storage_connection_string,
        settings.initial_admin_password,
    ):
        assert secret.get_secret_value() not in text
