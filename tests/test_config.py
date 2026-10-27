"""Settings and startup validation."""

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.models import Role

SECRET_A = "a-secret-with-at-least-32-bytes-1234"
SECRET_B = "another-secret-with-32-bytes-or-more"
# Values that must never appear in an error message.
SENSITIVE = [
    SECRET_A,
    SECRET_B,
    "postgresql+asyncpg://u:p@h/d",
    "AccountKey=abc",
    "admin-password-123",
    "short",  # invalid input values must not be echoed either
    "not-a-number",
]

VALID_ENV = {
    "APP_ENV": "local",
    "BASE_URL": "http://localhost:8000",
    "DATABASE_URL": "postgresql+asyncpg://u:p@h/d",
    "AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;AccountKey=abc",
    "AZURE_STORAGE_CONTAINER": "silo-local-test",
    "JWT_SECRET": SECRET_A,
    "JWT_ISSUER": "silo",
    "JWT_AUDIENCE": "silo-local",
    "CSRF_SECRET": SECRET_B,
    "INITIAL_ADMIN_USERNAME": "Admin",
    "INITIAL_ADMIN_PASSWORD": "admin-password-123",
    "MAX_FILE_SIZE_BYTES": "1048576",
    "COOKIE_SECURE": "false",
}


def make(monkeypatch: pytest.MonkeyPatch, **overrides: str | None) -> Settings:
    """Build Settings from a clean environment; a value of None removes the variable."""
    # Start without any inherited variable that could change the result.
    for name in [*VALID_ENV, *Settings.model_fields]:
        monkeypatch.delenv(name.upper(), raising=False)
    for name, value in {**VALID_ENV, **overrides}.items():
        if value is not None:
            monkeypatch.setenv(name, value)
    return Settings(_env_file=None)  # type: ignore[call-arg]


def error_text(monkeypatch: pytest.MonkeyPatch, **overrides: str | None) -> str:
    """Return the validation error text for an invalid configuration."""
    with pytest.raises(ValidationError) as info:
        make(monkeypatch, **overrides)
    return str(info.value)


def test_valid_configuration_uses_spec_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Defaults match the specified values."""
    s = make(monkeypatch)
    assert s.registration_mode == "approval"
    assert (s.jwt_access_minutes, s.refresh_token_days, s.session_max_days) == (15, 7, 30)
    assert s.upload_chunk_bytes == 4 * 1024 * 1024
    assert (s.sas_url_ttl_seconds, s.public_link_max_hours) == (300, 168)
    assert (s.login_max_failed, s.login_lock_minutes, s.password_min_length) == (10, 15, 12)
    assert s.enable_docs is False
    assert s.jwt_secret_previous is None
    # COOKIE_SECURE is true unless explicitly turned off.
    assert make(monkeypatch, COOKIE_SECURE=None).cookie_secure is True


def test_initial_admin_username_follows_the_username_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    """INITIAL_ADMIN_USERNAME is lowercased; one that breaks the rule stops the startup."""
    assert make(monkeypatch).initial_admin_username == "admin"
    assert "initial_admin_username" in error_text(monkeypatch, INITIAL_ADMIN_USERNAME="a b")


@pytest.mark.parametrize(
    "name",
    [
        "APP_ENV",
        "BASE_URL",
        "DATABASE_URL",
        "AZURE_STORAGE_CONNECTION_STRING",
        "AZURE_STORAGE_CONTAINER",
        "JWT_SECRET",
        "JWT_ISSUER",
        "JWT_AUDIENCE",
        "CSRF_SECRET",
        "INITIAL_ADMIN_USERNAME",
        "INITIAL_ADMIN_PASSWORD",
        "MAX_FILE_SIZE_BYTES",
    ],
)
def test_missing_required_variable_is_refused(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Every required variable must be set."""
    assert name.lower() in error_text(monkeypatch, **{name: None})


@pytest.mark.parametrize("name", ["JWT_SECRET", "CSRF_SECRET", "JWT_SECRET_PREVIOUS"])
def test_short_secret_is_refused(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Secrets must be at least 32 bytes."""
    assert f"{name} must be at least 32 bytes" in error_text(monkeypatch, **{name: "short"})


def test_secret_length_is_measured_in_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """16 two-byte characters are 32 bytes and therefore accepted."""
    assert make(monkeypatch, JWT_SECRET="é" * 16)


def test_equal_jwt_and_csrf_secret_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """JWT_SECRET and CSRF_SECRET must differ."""
    assert "JWT_SECRET and CSRF_SECRET must be different" in error_text(
        monkeypatch, CSRF_SECRET=SECRET_A
    )


@pytest.mark.parametrize("env", ["staging", "prod"])
@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("COOKIE_SECURE", "false"),
        ("ENABLE_DOCS", "true"),
        ("REGISTRATION_MODE", "open"),
        ("BASE_URL", "http://silo.example"),
    ],
)
def test_unsafe_setting_is_refused_in_staging_and_prod(
    monkeypatch: pytest.MonkeyPatch, env: str, variable: str, value: str
) -> None:
    """staging and prod refuse insecure cookies, docs, open registration and an http BASE_URL."""
    assert variable in error_text(monkeypatch, APP_ENV=env, **{variable: value})


def test_unsafe_setting_and_placeholders_are_allowed_locally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The settings staging and prod refuse are fine for APP_ENV=local (also CHANGE values)."""
    assert make(
        monkeypatch,
        ENABLE_DOCS="true",
        REGISTRATION_MODE="open",
        JWT_SECRET="CHANGE-me-" + "x" * 40,
    )


def test_staging_with_safe_settings_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    """A correctly configured staging environment is accepted."""
    assert make(
        monkeypatch, APP_ENV="staging", COOKIE_SECURE="true", BASE_URL="https://silo.example"
    )


def test_error_messages_never_contain_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """Messages name the variable, never its value."""
    texts = [
        error_text(monkeypatch, JWT_SECRET="short", CSRF_SECRET="short"),
        error_text(monkeypatch, CSRF_SECRET=SECRET_A),
        error_text(monkeypatch, APP_ENV="prod", COOKIE_SECURE="false", ENABLE_DOCS="true"),
        error_text(monkeypatch, MAX_FILE_SIZE_BYTES="not-a-number", APP_ENV="nonsense"),
        error_text(monkeypatch, DATABASE_URL=None, INITIAL_ADMIN_PASSWORD=None),
    ]
    for text in texts:
        for value in SENSITIVE:
            assert value not in text


def test_quota_for_role(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each role has its own quota; defaults are 1, 5 and 10 GiB."""
    s = make(monkeypatch, QUOTA_USER_BYTES="10")
    assert s.quota_for_role(Role.user) == 10
    assert s.quota_for_role(Role.team_lead) == 5 * 1024**3
    assert s.quota_for_role(Role.admin) == 10 * 1024**3


@pytest.mark.parametrize(
    "name",
    [
        "SAS_URL_TTL_SECONDS",
        "LOGIN_MAX_FAILED",
        "LOGIN_LOCK_MINUTES",
        "UPLOAD_CHUNK_BYTES",
        "MAX_FILE_SIZE_BYTES",
        "JWT_ACCESS_MINUTES",
        "PUBLIC_LINK_MAX_HOURS",
        "QUOTA_USER_BYTES",
    ],
)
@pytest.mark.parametrize("value", ["0", "-1"])
def test_numbers_must_be_positive(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    """Zero or negative numbers would break downloads, login or uploads at runtime."""
    assert name.lower() in error_text(monkeypatch, **{name: value})


@pytest.mark.parametrize("value", ["-1", "65536"])
def test_metrics_port_must_be_a_valid_port(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """METRICS_PORT is 0 (off) or a TCP port; anything else stops the startup."""
    assert "metrics_port" in error_text(monkeypatch, METRICS_PORT=value)


@pytest.mark.parametrize("password", ["short", "admin"])
def test_initial_admin_password_follows_the_policy(
    monkeypatch: pytest.MonkeyPatch, password: str
) -> None:
    """The first admin gets no weaker password than anybody else (too short, or the username)."""
    text = error_text(monkeypatch, INITIAL_ADMIN_PASSWORD=password, INITIAL_ADMIN_USERNAME="admin")
    assert "INITIAL_ADMIN_PASSWORD" in text
    assert password not in text.replace("INITIAL_ADMIN_PASSWORD", "")


@pytest.mark.parametrize("env", ["staging", "prod"])
@pytest.mark.parametrize(
    "variable",
    [
        "JWT_SECRET",
        "CSRF_SECRET",
        "INITIAL_ADMIN_PASSWORD",
        "DATABASE_URL",
        "AZURE_STORAGE_CONTAINER",
    ],
)
def test_placeholders_are_refused_in_staging_and_prod(
    monkeypatch: pytest.MonkeyPatch, env: str, variable: str
) -> None:
    """Values copied from .env.dev.example (they contain CHANGE) must not run in staging/prod."""
    safe = {"APP_ENV": env, "COOKIE_SECURE": "true", "BASE_URL": "https://silo.example"}
    placeholder = "CHANGE-me-" + "x" * 40
    assert variable in error_text(monkeypatch, **safe, **{variable: placeholder})


@pytest.mark.parametrize(
    "value",
    [
        "https://silo.example/app",
        "silo.example",
        "ftp://silo.example",
        "https://x?a=1",
        "http://h:99999",
    ],
)
def test_base_url_must_be_an_origin(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """A path, query, other scheme or bad port would break link URLs and the Origin check."""
    assert "base_url" in error_text(monkeypatch, BASE_URL=value).lower()


def test_base_url_trailing_slash_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Link URLs are built as BASE_URL + /s/..., so no double slash."""
    assert make(monkeypatch, BASE_URL="http://localhost:8000/").base_url == "http://localhost:8000"
