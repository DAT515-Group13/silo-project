"""Operational endpoints /healthz and /readyz."""

import asyncio
import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.metrics import DEPENDENCY_UP, STORAGE_USED
from app.routers.common import DbSession, Store
from app.services import users

logger = logging.getLogger("silo")

DATABASE_TIMEOUT_SECONDS = 5
# The stored-bytes gauge is telemetry: it may add at most this much to a readiness probe.
STORAGE_SUM_TIMEOUT_SECONDS = 1

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness: answers 200 without checking any dependency."""
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(session: DbSession, store: Store) -> JSONResponse:
    """Readiness: ``SELECT 1`` on PostgreSQL and ``BlobStore.ping()``.

    Returns 200 ``{"status": "ok"}`` when both work, otherwise 503 ``{"status": "unavailable"}``.
    Both checks always run, so the log shows every failing dependency. The response body never
    says which one failed: details go to the log only. When the database works, the total stored
    bytes are also published as a gauge (for the "storage almost full" alert); a failure there
    never changes the answer.
    """
    healthy = True

    # Check 1: the database answers a trivial query.
    try:
        # A database that accepts the connection but does not answer must not hang the probe.
        async with asyncio.timeout(DATABASE_TIMEOUT_SECONDS):
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        # Log the exception type only: the message of a driver error can contain the DSN.
        logger.warning("Readiness check failed: database (%s)", type(exc).__name__)
        healthy = False
        DEPENDENCY_UP.labels("database").set(0)
    else:
        DEPENDENCY_UP.labels("database").set(1)
        await _publish_storage_used(session)

    # Check 2: the configured blob container is reachable.
    try:
        await store.ping()
    except Exception as exc:
        logger.warning("Readiness check failed: blob storage (%s)", type(exc).__name__)
        healthy = False
        DEPENDENCY_UP.labels("blob_storage").set(0)
    else:
        DEPENDENCY_UP.labels("blob_storage").set(1)

    if healthy:
        return JSONResponse({"status": "ok"})
    return JSONResponse({"status": "unavailable"}, status_code=503)


async def _publish_storage_used(session: DbSession) -> None:
    """Set ``silo_storage_used_bytes``; telemetry must never make the pod unready."""
    try:
        async with asyncio.timeout(STORAGE_SUM_TIMEOUT_SECONDS):
            STORAGE_USED.set(await users.total_used_bytes(session))
    except Exception as exc:
        logger.warning("Could not read the total stored bytes (%s)", type(exc).__name__)
