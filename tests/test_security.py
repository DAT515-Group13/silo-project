"""Passwords, access tokens, random tokens and CSRF tokens."""

import hashlib
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import anyio
import jwt
import pytest
from argon2 import PasswordHasher

from app import security
from app.errors import InvalidToken, ValidationFailed

SECRET = "s" * 40
OLD_SECRET = "o" * 40
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


def test_key_id_is_8_hex_characters_and_differs_per_secret() -> None:
    """kid is the first 8 hex characters of SHA-256 of the secret (Q1)."""
    assert security.key_id(SECRET) == hashlib.sha256(SECRET.encode()).hexdigest()[:8]
    assert security.key_id(SECRET) != security.key_id(OLD_SECRET)


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
        pytest.param(_claims(sub="not-a-number"), id="sub is not a number"),
        pytest.param(_claims(sid="not-a-uuid"), id="sid is not a uuid"),
        pytest.param(_claims(jti="not-a-uuid"), id="jti is not a uuid"),
        pytest.param(lambda: "", id="empty text"),
        pytest.param(lambda: "abc", id="plain text"),
        pytest.param(lambda: "a.b.c", id="three dots, not a JWT"),
        pytest.param(lambda: "Bearer x", id="bearer prefix"),
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


def test_previous_secret_is_accepted_only_when_listed() -> None:
    """During rotation a token signed with JWT_SECRET_PREVIOUS still works, unless expired."""
    token = make_token(OLD_SECRET)
    assert decode(token, [SECRET, OLD_SECRET]).user_id == 42
    with pytest.raises(InvalidToken):
        decode(token, [SECRET])
    expired = make_token(OLD_SECRET, now=datetime.now(UTC) - timedelta(hours=1))
    with pytest.raises(InvalidToken):
        decode(expired, [SECRET, OLD_SECRET])


# --- Passwords -----------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_password_hash_and_verify() -> None:
    """A correct password verifies; a wrong one gives False; hashes are salted."""
    first = await security.hash_password("correct horse")
    second = await security.hash_password("correct horse")
    assert first != second
    assert first.startswith("$argon2id$")
    assert await security.verify_password(first, "correct horse") is True
    assert await security.verify_password(first, "wrong horse") is False


@pytest.mark.anyio
async def test_malformed_hash_is_a_failed_login_not_an_error() -> None:
    """A broken stored hash gives False instead of an exception."""
    assert await security.verify_password("not a hash", "whatever") is False
    assert await security.verify_password("", "whatever") is False


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
    assert security.MAX_PARALLEL_HASHES == 4


def test_weaker_hash_needs_rehash() -> None:
    """A hash made with weaker parameters is replaced after a successful login."""
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("pw")
    assert security.password_needs_rehash(weak) is True
    assert security.password_needs_rehash(security._hasher.hash("pw")) is False


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


# --- Random tokens -------------------------------------------------------------------------------


def test_refresh_tokens_are_random_and_43_characters_long() -> None:
    """secrets.token_urlsafe(32) gives 43 URL-safe characters, never repeated."""
    tokens = {security.generate_refresh_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(token) == 43 for token in tokens)


# --- CSRF tokens ---------------------------------------------------------------------------------


def test_csrf_token_needs_its_own_secret_and_session() -> None:
    """A token verifies only for the secret and binding it was made for."""
    token = security.create_csrf_token(SECRET, "session-1")
    assert security.verify_csrf_token(token, secret=SECRET, binding="session-1") is True
    assert security.verify_csrf_token(token, secret=SECRET, binding="session-2") is False
    assert security.verify_csrf_token(token, secret=OLD_SECRET, binding="session-1") is False
    # Every token has a fresh random part.
    assert security.create_csrf_token(SECRET, "b") != security.create_csrf_token(SECRET, "b")


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
