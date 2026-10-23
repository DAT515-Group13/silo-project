"""Pure security helpers: Argon2 passwords, JWT access tokens, random tokens, CSRF tokens.

No database and no settings access: secrets and parameters are passed in, which keeps every
function easy to test.
"""

import hashlib
import hmac
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache

import anyio.to_thread
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.errors import InvalidToken, ValidationFailed

ACCESS_TOKEN_ALGORITHM = "HS256"  # noqa: S105 - algorithm name, not a secret
JWT_LEEWAY_SECONDS = 10
PASSWORD_MAX_LENGTH = 128

_REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "sid"]

# RFC 9106 low-memory profile, above the OWASP minimum (19 MiB, t=2, p=1).
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)


# --- Passwords ---------------------------------------------------------------


def _verify(password_hash: str, password: str) -> bool:
    """Check a password against a hash; a wrong password and a malformed hash both give False.

    Neither case may become a server error: both are just a failed login.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


async def hash_password(password: str) -> str:
    """Hash a password with Argon2id. Runs in a worker thread: hashing is CPU and memory heavy."""
    return await anyio.to_thread.run_sync(_hasher.hash, password)


async def verify_password(password_hash: str, password: str) -> bool:
    """Return True if the password matches the hash, False for a wrong password or bad hash."""
    return await anyio.to_thread.run_sync(_verify, password_hash, password)


def password_needs_rehash(password_hash: str) -> bool:
    """Return True if the hash was made with weaker parameters than the current ones.

    The login service stores a new hash after a successful login when this is True.
    """
    return _hasher.check_needs_rehash(password_hash)


@cache
def _dummy_hash() -> str:
    """A hash of a random password, made once and only when first needed."""
    return _hasher.hash(secrets.token_urlsafe(16))


def _verify_dummy(password: str) -> None:
    _verify(_dummy_hash(), password)


async def verify_dummy_password(password: str) -> None:
    """Spend the same time as a real check so timing does not reveal account existence.

    Called when the username is unknown or the account is locked.
    """
    await anyio.to_thread.run_sync(_verify_dummy, password)


def check_password_policy(password: str, username: str, min_length: int) -> None:
    """Check the rules for a new password.

    The password must be between ``min_length`` and ``PASSWORD_MAX_LENGTH`` characters and must
    not equal the username (case-insensitive). The common-passwords list is added in phase 6.

    Raises:
        ValidationFailed: with one ``{"field": "password", ...}`` entry per broken rule.
    """
    problems: list[str] = []
    if len(password) < min_length:
        problems.append(f"Password must be at least {min_length} characters long.")
    if len(password) > PASSWORD_MAX_LENGTH:
        problems.append(f"Password must be at most {PASSWORD_MAX_LENGTH} characters long.")
    if password.casefold() == username.casefold():
        problems.append("Password must not be the same as the username.")
    if problems:
        raise ValidationFailed([{"field": "password", "message": m} for m in problems])


# --- Access tokens -----------------------------------------------------------


@dataclass(frozen=True)
class AccessClaims:
    """The verified claims of an access token that the rest of the app needs."""

    user_id: int
    session_id: uuid.UUID
    jti: uuid.UUID
    issued_at: datetime
    expires_at: datetime


def key_id(secret: str) -> str:
    """Return the ``kid`` header value for a signing secret: 8 hex characters of its SHA-256.

    It identifies which secret signed a token (current or previous during rotation) without
    revealing the secret.
    """
    return hashlib.sha256(secret.encode()).hexdigest()[:8]


def create_access_token(
    *,
    user_id: int,
    session_id: uuid.UUID,
    secret: str,
    issuer: str,
    audience: str,
    ttl: timedelta,
    now: datetime | None = None,
) -> str:
    """Create an HS256 access token.

    It carries no role, username, status or quota: those are read from the database on every
    request. The header contains ``kid`` (see ``key_id``). ``now`` exists for tests.
    """
    now = now or datetime.now(UTC)
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": str(user_id),
        "sid": str(session_id),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        "typ": "access",
    }
    return jwt.encode(
        payload, secret, algorithm=ACCESS_TOKEN_ALGORITHM, headers={"kid": key_id(secret)}
    )


def decode_access_token(
    token: str, *, secrets: Sequence[str], issuer: str, audience: str
) -> AccessClaims:
    """Verify a token against the given secrets (current first, then previous).

    Checks signature, algorithm (HS256 only, so ``alg=none`` is rejected), required claims,
    ``iss``, ``aud``, expiry (10 s leeway) and ``typ == "access"``. The secret whose ``kid``
    matches the header is tried first. A later secret is tried only after a signature failure,
    so an expired or wrong-audience token is rejected immediately.

    Raises:
        InvalidToken: for every failure, without details (one answer for all causes).
    """
    # Step 2a: order the secrets so the one named by `kid` is tried first.
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError as exc:
        raise InvalidToken from exc
    ordered = sorted(secrets, key=lambda candidate: key_id(candidate) != kid)

    # Step 2b: verify with each secret in turn.
    payload: dict | None = None
    for secret in ordered:
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[ACCESS_TOKEN_ALGORITHM],
                issuer=issuer,
                audience=audience,
                leeway=JWT_LEEWAY_SECONDS,
                options={"require": _REQUIRED_CLAIMS},
            )
            break
        except jwt.InvalidSignatureError:
            continue  # maybe signed with the previous secret
        except jwt.PyJWTError as exc:
            raise InvalidToken from exc
    if payload is None:
        raise InvalidToken

    # Step 2c: refresh tokens and other JWTs must not work as access tokens.
    if payload.get("typ") != "access":
        raise InvalidToken
    try:
        return AccessClaims(
            user_id=int(payload["sub"]),
            session_id=uuid.UUID(payload["sid"]),
            jti=uuid.UUID(payload["jti"]),
            issued_at=datetime.fromtimestamp(payload["iat"], UTC),
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise InvalidToken from exc


# --- Random tokens -----------------------------------------------------------


def generate_refresh_token() -> str:
    """Return a random 256-bit URL-safe token (43 characters), for refresh tokens and links."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest (64 characters) that is stored instead of the token.

    A fast hash is enough: the input is 256 random bits, so it cannot be guessed or brute forced.
    """
    return hashlib.sha256(token.encode()).hexdigest()


# --- CSRF tokens (pages only) ---------------------------------------


def _csrf_mac(secret: str, binding: str, nonce: str) -> str:
    """HMAC-SHA256 of ``binding`` and ``nonce`` under the CSRF secret, as hex."""
    message = f"{binding}.{nonce}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def create_csrf_token(secret: str, binding: str) -> str:
    """Create a signed double-submit token: ``<nonce>.<HMAC(secret, binding + nonce)>``.

    ``binding`` ties the token to its owner: the session ID for logged-in users, or a random
    pre-session value for the login and register forms. The same token goes into a cookie and a
    hidden form field.
    """
    nonce = secrets.token_urlsafe(16)
    return f"{nonce}.{_csrf_mac(secret, binding, nonce)}"


def verify_csrf_token(token: str, *, secret: str, binding: str) -> bool:
    """Return True if the token was issued for this ``binding`` with this secret.

    Cookie and form field must also be compared with each other by the caller, using
    ``hmac.compare_digest``.
    """
    nonce, separator, mac = token.partition(".")
    if not separator or not nonce:
        return False
    # Constant-time comparison, so response time does not reveal how much of the MAC matched.
    return hmac.compare_digest(mac, _csrf_mac(secret, binding, nonce))
