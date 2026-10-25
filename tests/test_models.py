"""Table definitions and the database helpers."""

from app.db import create_engine, create_session_factory
from app.models import Base
from tests.conftest import make_settings

EXPECTED_TABLES = {
    "users",
    "auth_sessions",
    "refresh_tokens",
    "teams",
    "team_members",
    "files",
    "file_shares",
    "share_links",
    "audit_log",
}


def test_metadata_contains_the_nine_tables() -> None:
    """All tables are defined, no more and no fewer."""
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_users_have_username_and_no_email() -> None:
    """Accounts are identified by a lowercase username of at most 32 characters (D16)."""
    users = Base.metadata.tables["users"]
    assert "email" not in users.c
    assert users.c.username.type.length == 32
    assert users.c.username.unique
    audit = Base.metadata.tables["audit_log"]
    assert "actor_email" not in audit.c
    assert audit.c.actor_username.type.length == 32


def test_all_timestamps_are_timezone_aware() -> None:
    """Every datetime column is timestamptz."""
    for table in Base.metadata.tables.values():
        for column in table.c:
            if column.type.python_type.__name__ == "datetime":
                assert column.type.timezone, f"{table.name}.{column.name}"


def test_engine_and_session_factory_are_created_without_connecting() -> None:
    """Creating the engine opens no connection; sessions do not expire objects on commit."""
    settings = make_settings()
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    assert engine.url.drivername == "postgresql+asyncpg"
    assert factory.kw["expire_on_commit"] is False
