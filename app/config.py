"""Typed settings read from environment variables, with startup validation.

The app refuses to start on an invalid configuration. Error messages name the variable and
never its value, so a misconfigured secret does not end up in logs.
"""

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import PositiveInt, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.errors import ValidationFailed
from app.models import Role
from app.schemas.common import Username
from app.security import check_password_policy

_GIB = 1024**3
_MIB = 1024**2
_MIN_SECRET_BYTES = 32

# Environments where the safe settings are enforced.
_STRICT_ENVS = {"staging", "prod"}
# Marks the values to replace in .env.dev.example.
_PLACEHOLDER_MARK = "CHANGE"


class Settings(BaseSettings):
    """All configuration of Silo. Secrets have no defaults."""

    # hide_input_in_errors: a validation error must never echo a secret value back.
    model_config = SettingsConfigDict(extra="ignore", hide_input_in_errors=True)

    app_env: Literal["local", "test", "dev", "staging", "prod"]
    base_url: str
    database_url: SecretStr
    azure_storage_connection_string: SecretStr
    azure_storage_container: str

    jwt_secret: SecretStr
    jwt_secret_previous: SecretStr | None = None
    jwt_issuer: str
    jwt_audience: str
    jwt_access_minutes: PositiveInt = 15
    refresh_token_days: PositiveInt = 7
    session_max_days: PositiveInt = 30
    csrf_secret: SecretStr
    cookie_secure: bool = True

    registration_mode: Literal["open", "approval", "closed"] = "approval"
    initial_admin_username: Username
    initial_admin_password: SecretStr

    quota_user_bytes: PositiveInt = 1 * _GIB
    quota_team_lead_bytes: PositiveInt = 5 * _GIB
    quota_admin_bytes: PositiveInt = 10 * _GIB
    max_file_size_bytes: PositiveInt
    upload_chunk_bytes: PositiveInt = 4 * _MIB
    sas_url_ttl_seconds: PositiveInt = 300
    public_link_max_hours: PositiveInt = 168

    login_max_failed: PositiveInt = 5
    login_lock_minutes: PositiveInt = 15
    password_min_length: PositiveInt = 12
    enable_docs: bool = False

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, value: str) -> str:
        """BASE_URL is an origin (scheme and host, optional port), without a trailing slash.

        A path would give link URLs the router does not serve, and the Origin check compares
        only the origin.
        """
        parts = urlsplit(value.strip())
        try:
            parts.port  # noqa: B018 - raises ValueError for a bad port
        except ValueError:
            raise ValueError("BASE_URL has an invalid port.") from None
        valid = (
            parts.scheme in ("http", "https")
            and parts.hostname
            and parts.path in ("", "/")
            and not (parts.query or parts.fragment or parts.username or parts.password)
        )
        if not valid:
            raise ValueError("BASE_URL must be an origin such as https://silo.example.")
        return value.strip().rstrip("/")

    @model_validator(mode="after")
    def _check_startup_rules(self) -> "Settings":
        """Refuse unsafe combinations.

        All problems are collected so the operator sees every wrong variable at once.
        """
        problems: list[str] = []

        # Secrets: at least 32 bytes each (compared in bytes, not characters).
        secrets = {
            "JWT_SECRET": self.jwt_secret,
            "CSRF_SECRET": self.csrf_secret,
            "JWT_SECRET_PREVIOUS": self.jwt_secret_previous,
        }
        for name, secret in secrets.items():
            if secret is not None and len(secret.get_secret_value().encode()) < _MIN_SECRET_BYTES:
                problems.append(f"{name} must be at least {_MIN_SECRET_BYTES} bytes long.")

        # A leaked CSRF secret must not let an attacker forge JWTs, and the other way round.
        if self.jwt_secret.get_secret_value() == self.csrf_secret.get_secret_value():
            problems.append("JWT_SECRET and CSRF_SECRET must be different.")

        # The initial admin password must follow the same policy as every other password.
        try:
            check_password_policy(
                self.initial_admin_password.get_secret_value(),
                self.initial_admin_username,
                self.password_min_length,
            )
        except ValidationFailed:
            problems.append("INITIAL_ADMIN_PASSWORD does not meet the password policy.")

        # Staging and prod must not run with development conveniences.
        if self.app_env in _STRICT_ENVS:
            # Placeholders copied from .env.dev.example are long enough to pass the checks above.
            placeholders = {
                "DATABASE_URL": self.database_url,
                "AZURE_STORAGE_CONNECTION_STRING": self.azure_storage_connection_string,
                "JWT_SECRET": self.jwt_secret,
                "JWT_SECRET_PREVIOUS": self.jwt_secret_previous,
                "CSRF_SECRET": self.csrf_secret,
                "INITIAL_ADMIN_PASSWORD": self.initial_admin_password,
            }
            for name, secret in placeholders.items():
                if secret is not None and _PLACEHOLDER_MARK in secret.get_secret_value():
                    problems.append(f"{name} still contains the placeholder {_PLACEHOLDER_MARK}.")
            if _PLACEHOLDER_MARK in self.azure_storage_container:
                problems.append(
                    f"AZURE_STORAGE_CONTAINER still contains the placeholder {_PLACEHOLDER_MARK}."
                )
            if not self.cookie_secure:
                problems.append(f"COOKIE_SECURE must be true when APP_ENV is {self.app_env}.")
            if self.enable_docs:
                problems.append(f"ENABLE_DOCS must be false when APP_ENV is {self.app_env}.")
            if not self.base_url.startswith("https://"):
                problems.append(
                    f"BASE_URL must start with https:// when APP_ENV is {self.app_env}."
                )
            if self.registration_mode == "open":
                problems.append(
                    f"REGISTRATION_MODE must not be 'open' when APP_ENV is {self.app_env}."
                )

        if problems:
            raise ValueError(" ".join(problems))
        return self

    def quota_for_role(self, role: Role) -> int:
        """Return the storage quota in bytes for a role."""
        return {
            Role.user: self.quota_user_bytes,
            Role.team_lead: self.quota_team_lead_bytes,
            Role.admin: self.quota_admin_bytes,
        }[role]


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings, read from the environment on first use.

    Raises:
        pydantic.ValidationError: if the configuration is invalid (the app must not start).
    """
    return Settings()  # type: ignore[call-arg]  # required fields come from the environment
