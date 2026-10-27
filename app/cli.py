"""Admin commands, run as ``python -m app.cli <command>`` (architecture.md section 10).

``cleanup-orphans [--dry-run]`` removes blobs that no file row refers to. It is meant to run
as a scheduled job (for example a Kubernetes CronJob) with the same environment as the app.
Output contains counts only, never secrets.
"""

import argparse
import asyncio
import sys
from collections.abc import Sequence

from app.config import get_settings
from app.db import create_engine, create_session_factory
from app.errors import StorageUnavailable
from app.services.orphans import cleanup_orphans
from app.storage.azure_blob import create_blob_store


async def run_cleanup(dry_run: bool) -> int:
    """Run the orphan cleanup with the configured database and blob store; return an exit code."""
    settings = get_settings()
    engine = create_engine(settings)
    store = create_blob_store(settings)
    try:
        async with create_session_factory(engine)() as session:
            result = await cleanup_orphans(session, store, dry_run=dry_run)
    except StorageUnavailable:
        print("Blob storage is unavailable; the cleanup was stopped.", file=sys.stderr)
        return 1
    finally:
        await store.close()
        await engine.dispose()
    verb = "would delete" if dry_run else "deleted"
    print(f"Scanned {result.scanned} old blobs, {verb} {result.deleted} orphans.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the command line and run the chosen command."""
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="Silo admin commands")
    commands = parser.add_subparsers(dest="command", required=True)
    cleanup = commands.add_parser(
        "cleanup-orphans", help="delete blobs older than 24 hours that no file refers to"
    )
    cleanup.add_argument("--dry-run", action="store_true", help="only count, delete nothing")
    args = parser.parse_args(argv)
    return asyncio.run(run_cleanup(args.dry_run))


if __name__ == "__main__":
    raise SystemExit(main())
