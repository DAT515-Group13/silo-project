"""Page-based listing for every paginated endpoint.

Responses have the shape ``{items, total, page, size}``; ``page >= 1`` and ``1 <= size <= 100``
are already enforced by the router parameters (``PageNumber``, ``PageSize``).
"""

from collections.abc import Sequence
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession


async def fetch_page(
    session: AsyncSession, statement: Select[Any], *, page: int, size: int
) -> tuple[Sequence[Row[Any]], int]:
    """Run ``statement`` for one page and count all matching rows.

    ``statement`` must already be ordered (a stable order, so pages do not overlap). Runs in
    the caller's transaction. Returns the rows of the page and the total number of rows.
    """
    # The count ignores ORDER BY, which only costs time in a COUNT(*).
    total = await session.scalar(
        select(func.count()).select_from(statement.order_by(None).subquery())
    )
    rows = (await session.execute(statement.limit(size).offset((page - 1) * size))).all()
    return rows, total or 0
