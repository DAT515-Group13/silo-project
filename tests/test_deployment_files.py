"""Static checks of the Docker files and .env.dev.example.

Nothing is built or started here: the files are only read.
"""

from pathlib import Path

import pytest

from app.config import Settings

ROOT = Path(__file__).resolve().parent.parent


def read(name: str) -> str:
    """Return the text of a file in the repository root."""
    return (ROOT / name).read_text()


def test_env_example_is_a_valid_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """The example file loads into valid Settings, so a copy with real values just works."""
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
    settings = Settings(_env_file=ROOT / ".env.dev.example")  # type: ignore[call-arg]
    assert settings.app_env == "local"
    assert settings.initial_admin_username == "admin"
    assert settings.cookie_secure is False


def test_env_example_has_placeholders_only() -> None:
    """Every secret in the example is marked CHANGE (no real secrets in the repo)."""
    text = read(".env.dev.example")
    for variable in (
        "POSTGRES_PASSWORD",
        "DATABASE_URL",
        "AZURE_STORAGE_CONNECTION_STRING",
        "JWT_SECRET",
        "CSRF_SECRET",
        "INITIAL_ADMIN_PASSWORD",
    ):
        line = next(line for line in text.splitlines() if line.startswith(f"{variable}="))
        assert "CHANGE" in line, variable


def test_dockerfile_runs_as_non_root_without_writing_bytecode() -> None:
    """The image uses a fixed non-root UID and the app writes nothing to disk."""
    text = read("Dockerfile")
    assert "USER 10001:10001" in text
    assert "PYTHONDONTWRITEBYTECODE=1" in text
    assert "--factory" in text
    assert "--proxy-headers" in text


def test_dockerignore_keeps_secrets_out_of_the_image() -> None:
    """Environment files and keys are excluded from the build context."""
    lines = read(".dockerignore").splitlines()
    assert ".env" in lines
    assert ".env.*" in lines
    assert ".git" in lines
