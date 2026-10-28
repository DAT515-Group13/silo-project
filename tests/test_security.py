"""Passwords, access tokens, random tokens and CSRF tokens."""

import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import anyio
import jwt
import pytest

from app import security
from app.errors import InvalidToken, ValidationFailed

SECRET = "s" * 40
ISSUER = "silo"
AUDIENCE = "silo-test"
SESSION_ID = uuid.UUID("c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f")
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def make_token(secret: str = SECRET, *, now: datetime | None = None, **kwargs: object) -> str:
    """Create a valid access token; ``now`` defaults to the real current time."""
    return security.create_access_token(
        user_id=42,
        session_id=SESSION_ID,
        secret=secret,
        issuer=kwargs.pop("issuer", ISSUER),  # type: ignore[arg-type]
        audience=kwargs.pop("audience", AUDIENCE),  # type: ignore[arg-type]
        ttl=kwargs.pop("ttl", timedelta(minutes=15)),  # type: ignore[arg-type]
        now=now,
    )


def decode(token: str, secrets: list[str] | None = None) -> security.AccessClaims:
    return security.decode_access_token(
        token, secrets=secrets or [SECRET], issuer=ISSUER, audience=AUDIENCE
    )


def raw_token(overrides: dict, *, key: str | None = SECRET, algorithm: str = "HS256") -> str:
    """Encode a token by hand, to build invalid ones. A value of None removes the claim."""
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "42",
        "sid": str(SESSION_ID),
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "typ": "access",
        **overrides,
    }
    claims = {name: value for name, value in claims.items() if value is not None}
    return jwt.encode(claims, key, algorithm=algorithm)


# --- Access tokens -------------------------------------------------------------------------------


def test_valid_token_gives_the_claims() -> None:
    """A correct token decodes to user, session and times."""
    claims = decode(make_token(now=datetime.now(UTC)))
    assert claims.user_id == 42
    assert claims.session_id == SESSION_ID
    assert claims.expires_at - claims.issued_at == timedelta(minutes=15)


def test_token_header_has_kid_and_payload_has_no_personal_data() -> None:
    """The header names the key; role, username, status and quota are never in the token."""
    token = make_token()
    assert jwt.get_unverified_header(token)["kid"] == security.key_id(SECRET)
    payload = jwt.decode(token, options={"verify_signature": False})
    assert set(payload) == {"iss", "aud", "sub", "sid", "iat", "nbf", "exp", "jti", "typ"}
    assert payload["typ"] == "access"


def _claims(**overrides: object) -> Callable[[], str]:
    """A factory for a hand-made token with these claims changed; built when the test runs."""
    return lambda: raw_token(overrides)


@pytest.mark.parametrize(
    "build_token",
    [
        pytest.param(lambda: raw_token({}, key=None, algorithm="none"), id="alg none"),
        pytest.param(_claims(aud="silo-prod"), id="wrong audience"),
        pytest.param(_claims(iss="someone-else"), id="wrong issuer"),
        pytest.param(_claims(typ="refresh"), id="typ refresh"),
        pytest.param(_claims(typ=None), id="missing typ"),
        pytest.param(_claims(sid=None), id="missing sid"),
        pytest.param(_claims(sub=None), id="missing sub"),
        pytest.param(_claims(exp=None), id="missing exp"),
        pytest.param(_claims(sid="not-a-uuid"), id="sid is not a uuid"),
        pytest.param(lambda: "a.b.c", id="three dots, not a JWT"),
    ],
)
def test_invalid_tokens_are_rejected(build_token: Callable[[], str]) -> None:
    """Unsigned, wrongly claimed, malformed or non-JWT tokens all give InvalidToken."""
    with pytest.raises(InvalidToken):
        decode(build_token())


def test_expired_token_is_rejected_outside_the_leeway() -> None:
    """Expiry has a 10 s leeway: 5 s past is accepted, 11 s past is not."""
    issued = datetime.now(UTC) - timedelta(minutes=15)
    assert decode(make_token(now=issued - timedelta(seconds=5)))
    with pytest.raises(InvalidToken):
        decode(make_token(now=issued - timedelta(seconds=11)))


# --- Passwords -----------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_password_hash_and_verify() -> None:
    """A correct password verifies; a wrong one or a broken hash gives False; hashes are salted."""
    first = await security.hash_password("correct horse")
    second = await security.hash_password("correct horse")
    assert first != second
    assert first.startswith("$argon2id$")
    assert await security.verify_password(first, "correct horse") is True
    assert await security.verify_password(first, "wrong horse") is False
    # A broken stored hash is a failed login, not an exception.
    assert await security.verify_password("not a hash", "whatever") is False


@pytest.mark.anyio
async def test_same_text_in_different_unicode_forms_is_the_same_password() -> None:
    """ "é" as one code point and as "e" plus an accent hash and verify alike (NFKC)."""
    composed, decomposed = "caf\u00e9-horse-battery", "cafe\u0301-horse-battery"
    assert composed != decomposed
    stored = await security.hash_password(composed)
    assert await security.verify_password(stored, decomposed) is True
    assert await security.verify_password(stored, "cafe-horse-battery") is False


@pytest.mark.anyio
async def test_password_checks_wait_for_the_hash_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the limiter at 1, two parallel verifications never run at the same time."""
    running = 0
    most = 0
    lock = threading.Lock()

    def slow_verify(password_hash: str, password: str) -> bool:
        nonlocal running, most
        with lock:
            running += 1
            most = max(most, running)
        time.sleep(0.05)
        with lock:
            running -= 1
        return False

    monkeypatch.setattr(security, "_verify", slow_verify)
    monkeypatch.setattr(security, "_hash_limiter", anyio.CapacityLimiter(1))
    async with anyio.create_task_group() as group:
        for _ in range(2):
            group.start_soon(security.verify_password, "hash", "password")
    assert most == 1


@pytest.mark.parametrize(
    ("password", "expected_fragment"),
    [
        ("short", "at least 12"),
        ("x" * 129, "at most 128"),
        ("Anna.Example", "same as the username"),
    ],
)
def test_password_policy_rejects(password: str, expected_fragment: str) -> None:
    """Too short, too long and equal to the username (any case) are rejected."""
    with pytest.raises(ValidationFailed) as info:
        security.check_password_policy(password, "anna.example", 12)
    assert any(expected_fragment in e["message"] for e in info.value.errors)
    assert all(e["field"] == "password" for e in info.value.errors)


def test_password_policy_accepts_a_good_password() -> None:
    """A password within the limits and different from the username passes."""
    security.check_password_policy("a" * 12, "anna", 12)
    security.check_password_policy("a" * 128, "anna", 12)


# --- CSRF tokens ---------------------------------------------------------------------------------


def test_tampered_or_malformed_csrf_token_is_rejected() -> None:
    """Changing any part, or sending something that is not a token, fails without an error."""
    token = security.create_csrf_token(SECRET, "session-1")
    nonce, mac = token.split(".")
    flipped = "0" if mac[-1] != "0" else "1"  # always differs from the real last character
    for bad in (
        f"{nonce}x.{mac}",
        f"{nonce}.{mac[:-1]}{flipped}",
        "",
        "nodot",
        ".",
        f".{mac}",
        f"{nonce}.é",  # non-ASCII must give False, not a TypeError
        f"é.{mac}",
    ):
        assert security.verify_csrf_token(bad, secret=SECRET, binding="session-1") is False
