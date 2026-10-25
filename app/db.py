"""Async database engine, session factory and the ``get_db`` dependency.

The engine and the session factory are created once at startup (``main.py`` lifespan) and kept
on ``app.state``. Services own their transactions, so nothing here commits.
"""

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import Settings

CONNECT_TIMEOUT_SECONDS = 5


def create_engine(settings: Settings) -> AsyncEngine:
    """Create the async engine for ``DATABASE_URL``.

    ``pool_pre_ping`` drops connections that PostgreSQL closed while the app was idle, so a
    database restart does not cause a burst of 500 errors. The connect timeout (asyncpg waits 60 s
    by default) keeps ``/readyz`` answering 503 quickly when PostgreSQL is unreachable.
    """
    return create_async_engine(
        settings.database_url.get_secret_value(),
        pool_pre_ping=True,
        connect_args={"timeout": CONNECT_TIMEOUT_SECONDS},
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create the session factory.

    ``expire_on_commit=False`` keeps loaded objects readable after a service's transaction ends,
    which routers rely on when building the response.
    """
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request, closed afterwards.

    It never begins or commits a transaction: the service functions do that with
    ``async with session.begin()``.
    """
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with session_factory() as session:
        yield session
