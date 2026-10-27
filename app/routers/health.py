"""Operational endpoints /healthz and /readyz."""

import asyncio
import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.routers.common import DbSession, Store

logger = logging.getLogger("silo")

DATABASE_TIMEOUT_SECONDS = 5

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
    says which one failed: details go to the log only.
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

    # Check 2: the configured blob container is reachable.
    try:
        await store.ping()
    except Exception as exc:
        logger.warning("Readiness check failed: blob storage (%s)", type(exc).__name__)
        healthy = False

    if healthy:
        return JSONResponse({"status": "ok"})
    return JSONResponse({"status": "unavailable"}, status_code=503)
