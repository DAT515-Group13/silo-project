"""Typed settings read from environment variables, with startup validation.

The app refuses to start on an invalid configuration. Error messages name the variable and
never its value, so a misconfigured secret does not end up in logs.
"""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.models import Role
from app.schemas.common import Username

_GIB = 1024**3
_MIB = 1024**2
_MIN_SECRET_BYTES = 32

# Environments where the safe settings are enforced.
_STRICT_ENVS = {"staging", "prod"}


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
    jwt_access_minutes: int = 15
    refresh_token_days: int = 7
    session_max_days: int = 30
    csrf_secret: SecretStr
    cookie_secure: bool = True

    registration_mode: Literal["open", "approval", "closed"] = "approval"
    initial_admin_username: Username
    initial_admin_password: SecretStr

    quota_user_bytes: int = 1 * _GIB
    quota_team_lead_bytes: int = 5 * _GIB
    quota_admin_bytes: int = 10 * _GIB
    max_file_size_bytes: int
    upload_chunk_bytes: int = 4 * _MIB
    sas_url_ttl_seconds: int = 300
    public_link_max_hours: int = 168

    login_max_failed: int = 5
    login_lock_minutes: int = 15
    password_min_length: int = 12
    enable_docs: bool = False

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

        # Staging and prod must not run with development conveniences.
        if self.app_env in _STRICT_ENVS:
            if not self.cookie_secure:
                problems.append(f"COOKIE_SECURE must be true when APP_ENV is {self.app_env}.")
            if self.enable_docs:
                problems.append(f"ENABLE_DOCS must be false when APP_ENV is {self.app_env}.")
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
