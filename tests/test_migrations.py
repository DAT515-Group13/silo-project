"""The first Alembic migration against the models.

The offline test renders the SQL and needs no database. Tests marked ``db`` run the migration on
a scratch database that is created and dropped on the server given by TEST_DATABASE_URL.
"""

import asyncio
import io
import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from app.models import Base
from tests.conftest import DEFAULT_TEST_DATABASE_URL

ROOT = Path(__file__).resolve().parent.parent
TABLES = set(Base.metadata.tables)
ENUM_TYPES = {"role", "user_status", "actor_type", "outcome"}
# Alembic cannot compare indexes built from text expressions ("created_at DESC") and reports them
# as changed on every run. They are covered by the SQL assertions in the offline test instead.
EXPRESSION_INDEXES = {
    "ix_audit_log_created_at",
    "ix_audit_log_actor_id_created_at",
    "ix_audit_log_action_created_at",
}


def alembic_config() -> Config:
    """Alembic configuration pointing at the repository's alembic.ini."""
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    return config


def test_offline_sql_contains_every_table_enum_and_index(monkeypatch: pytest.MonkeyPatch) -> None:
    """The migration renders valid PostgreSQL DDL without a database."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/offline")
    config = alembic_config()
    config.output_buffer = io.StringIO()
    command.upgrade(config, "head", sql=True)
    sql = config.output_buffer.getvalue()

    for table in TABLES:
        assert f"CREATE TABLE {table} " in sql
    for enum_type in ENUM_TYPES:
        assert f"CREATE TYPE {enum_type} AS ENUM" in sql
    assert "username VARCHAR(32) NOT NULL" in sql
    assert "actor_username VARCHAR(32)" in sql
    assert "email" not in sql.lower()
    assert "gen_random_uuid()" in sql
    assert "CREATE INDEX ix_audit_log_created_at ON audit_log (created_at DESC)" in sql
    assert "ix_audit_log_actor_id_created_at ON audit_log (actor_id, created_at DESC)" in sql
    assert "ix_audit_log_action_created_at ON audit_log (action, created_at DESC)" in sql
    assert "ix_audit_log_target_type_target_id" in sql
    assert "CHECK (used_bytes >= 0)" in sql
    assert "CHECK (size_bytes >= 0)" in sql


def test_migration_env_does_not_need_the_app_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The migration job only has DATABASE_URL (D13), so a missing variable is a clear error."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    config = alembic_config()
    config.output_buffer = io.StringIO()
    with pytest.raises(RuntimeError, match="DATABASE_URL is not set"):
        command.upgrade(config, "head", sql=True)


@pytest.fixture
def scratch_database_url(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Create an empty database on the test server, expose it as DATABASE_URL, drop it after."""
    server_url = make_url(os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL))
    name = f"silo_migration_{uuid.uuid4().hex[:8]}"

    async def admin(statement: str) -> None:
        engine = create_async_engine(
            server_url.set(database="postgres"), isolation_level="AUTOCOMMIT"
        )
        async with engine.connect() as connection:
            await connection.execute(text(statement))
        await engine.dispose()

    asyncio.run(admin(f'CREATE DATABASE "{name}"'))
    url = server_url.set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("DATABASE_URL", url)
    try:
        yield url
    finally:
        asyncio.run(admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


async def _inspect(url: str) -> tuple[set[str], set[str], list]:
    """Return the table names, enum type names and the models-vs-database differences."""
    engine = create_async_engine(url)
    async with engine.connect() as connection:
        tables = {
            row[0]
            for row in await connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        }
        enums = {
            row[0]
            for row in await connection.execute(
                text("SELECT typname FROM pg_type WHERE typtype = 'e'")
            )
        }

        def diff(sync_connection) -> list:
            context = MigrationContext.configure(sync_connection, opts={"compare_type": True})
            return compare_metadata(context, Base.metadata)

        differences = await connection.run_sync(diff)
    await engine.dispose()
    return tables, enums, differences


def _relevant(differences: list) -> list:
    """Drop the expression-index noise described at EXPRESSION_INDEXES."""
    result = []
    for entry in differences:
        operations = entry if isinstance(entry, list) else [entry]
        for operation in operations:
            kind, payload = operation[0], operation[1]
            if kind in {"add_index", "remove_index"} and payload.name in EXPRESSION_INDEXES:
                continue
            result.append(operation)
    return result


@pytest.mark.db
def test_upgrade_matches_models(scratch_database_url: str) -> None:
    """`alembic upgrade head` on an empty database creates exactly what models.py declares."""
    command.upgrade(alembic_config(), "head")
    tables, enums, differences = asyncio.run(_inspect(scratch_database_url))
    assert TABLES <= tables
    assert ENUM_TYPES <= enums
    assert _relevant(differences) == []


@pytest.mark.db
def test_downgrade_and_upgrade_again(scratch_database_url: str) -> None:
    """downgrade base removes every table and enum type; upgrade head works again."""
    config = alembic_config()
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    tables, enums, _ = asyncio.run(_inspect(scratch_database_url))
    assert not TABLES & tables
    assert not ENUM_TYPES & enums
    command.upgrade(config, "head")
    tables, _, _ = asyncio.run(_inspect(scratch_database_url))
    assert TABLES <= tables
