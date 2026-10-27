"""Input validation of the register endpoint. Fails before the database, so no ``db`` marker."""

import httpx
import pytest

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    ("username", "password", "field"),
    [
        ("x", "secret-value-1234", "username"),  # schema rule
        ("anna", "short", "password"),  # password policy, checked in the service
    ],
)
async def test_register_validation_errors_do_not_echo_the_password(
    client: httpx.AsyncClient, username: str, password: str, field: str
) -> None:
    """422 lists the bad field and never repeats the password."""
    response = await client.post(
        "/api/v1/auth/register", json={"username": username, "password": password}
    )
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation_error"
    assert [e["field"] for e in body["errors"]] == [field]
    assert password not in response.text
