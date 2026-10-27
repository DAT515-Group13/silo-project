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
