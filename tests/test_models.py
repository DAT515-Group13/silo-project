"""Table definitions."""

from app.models import Base


def test_all_timestamps_are_timezone_aware() -> None:
    """Every datetime column is timestamptz."""
    for table in Base.metadata.tables.values():
        for column in table.c:
            if column.type.python_type.__name__ == "datetime":
                assert column.type.timezone, f"{table.name}.{column.name}"
