"""Passwords, access tokens, random tokens and CSRF tokens."""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

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


def test_alg_none_is_rejected() -> None:
    """An unsigned token (alg=none) is never accepted."""
    with pytest.raises(InvalidToken):
        decode(raw_token({}, key=None, algorithm="none"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "silo-prod"},
        {"iss": "someone-else"},
        {"typ": "refresh"},
        {"typ": None},
        {"sid": None},
        {"sub": None},
        {"exp": None},
        {"sub": "not-a-number"},
        {"sid": "not-a-uuid"},
        {"jti": "not-a-uuid"},
    ],
)
def test_invalid_claims_are_rejected(overrides: dict) -> None:
    """Wrong aud, iss or typ and missing or malformed claims all give InvalidToken."""
    with pytest.raises(InvalidToken):
        decode(raw_token(overrides))


def test_garbage_is_rejected() -> None:
    """Text that is not a JWT gives InvalidToken, not a server error."""
    for text in ("", "abc", "a.b.c", "Bearer x"):
        with pytest.raises(InvalidToken):
            decode(text)


def test_expired_token_is_rejected_outside_the_leeway() -> None:
    """Expiry has a 10 s leeway: 5 s past is accepted, 11 s past is not."""
    issued = datetime.now(UTC) - timedelta(minutes=15)
    assert decode(make_token(now=issued - timedelta(seconds=5)))
    with pytest.raises(InvalidToken):
        decode(make_token(now=issued - timedelta(seconds=11)))


def test_previous_secret_is_accepted_only_when_listed() -> None:
    """During rotation a token signed with JWT_SECRET_PREVIOUS still works."""
    token = make_token(OLD_SECRET)
    assert decode(token, [SECRET, OLD_SECRET]).user_id == 42
    with pytest.raises(InvalidToken):
        decode(token, [SECRET])


def test_expired_token_of_the_previous_secret_is_rejected() -> None:
    """The fallback to the previous secret does not make expired tokens valid."""
    old = datetime.now(UTC) - timedelta(hours=1)
    with pytest.raises(InvalidToken):
        decode(make_token(OLD_SECRET, now=old), [SECRET, OLD_SECRET])


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
async def test_dummy_verification_does_not_fail() -> None:
    """The dummy check used for unknown usernames runs and returns nothing."""
    assert await security.verify_dummy_password("anything") is None


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


def test_hash_token_is_sha256_hex() -> None:
    """Only the SHA-256 hex digest is stored: 64 characters, deterministic."""
    assert security.hash_token("abc") == hashlib.sha256(b"abc").hexdigest()
    assert len(security.hash_token("abc")) == 64
    assert security.hash_token("abc") != security.hash_token("abd")


# --- CSRF tokens ---------------------------------------------------------------------------------


def test_csrf_token_needs_its_own_secret_and_session() -> None:
    """A token verifies only for the secret and binding it was made for."""
    token = security.create_csrf_token(SECRET, "session-1")
    assert security.verify_csrf_token(token, secret=SECRET, binding="session-1") is True
    assert security.verify_csrf_token(token, secret=SECRET, binding="session-2") is False
    assert security.verify_csrf_token(token, secret=OLD_SECRET, binding="session-1") is False


def test_csrf_tokens_are_unique() -> None:
    """Every token has a fresh random part."""
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
