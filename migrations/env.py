"""Async Alembic environment.

Reads only ``DATABASE_URL`` from the environment, not the full app settings, so the Kubernetes
migration job does not need the other secrets. Migrations never run from the app itself.
"""

import asyncio
import os

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.models import Base

target_metadata = Base.metadata


def _database_url() -> str:
    """Return ``DATABASE_URL`` or fail with a message that does not print any value."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set.")
    return url


def run_migrations_offline() -> None:
    """Emit the migration as SQL to the output buffer, without connecting to a database."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_migrations(connection: Connection) -> None:
    """Run the migrations on a synchronous connection handed over by the async engine."""
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Connect with asyncpg and run the migrations.

    ``NullPool``: this is a one-shot process, so no connection should outlive the run.
    """
    engine = create_async_engine(_database_url(), poolclass=NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(_run_migrations)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
