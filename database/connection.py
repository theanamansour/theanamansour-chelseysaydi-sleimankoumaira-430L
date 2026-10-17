import sqlite3
from contextlib import contextmanager
from pathlib import Path

from database.config import get_database_path


@contextmanager
def get_db(database_path=None):
    """Open a transaction against the shared database."""
    path = Path(database_path or get_database_path())
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
