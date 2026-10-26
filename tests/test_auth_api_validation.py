"""Input validation of the register endpoint. Fails before the database, so no ``db`` marker."""

import httpx
import pytest

pytestmark = pytest.mark.anyio


async def test_register_validation_errors_do_not_echo_the_password(
    client: httpx.AsyncClient,
) -> None:
    """422 lists the bad fields and never repeats the password."""
    response = await client.post(
        "/api/v1/auth/register", json={"username": "x", "password": "secret-value-1234"}
    )
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation_error"
    assert [e["field"] for e in body["errors"]] == ["username"]
    assert "secret-value-1234" not in response.text


async def test_register_short_password_is_422(client: httpx.AsyncClient) -> None:
    """The password policy runs in the service and answers with a field-level 422."""
    response = await client.post(
        "/api/v1/auth/register", json={"username": "anna", "password": "short"}
    )
    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "password"
