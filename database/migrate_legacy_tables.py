"""
Copy the records of Services 2, 4 and 8 (Sleiman Koumaira) from their old per-service
databases into the shared database, without deleting either database.

Rows keep their IDs, and each table's AUTOINCREMENT counter is copied too, so a deleted ID
is still never reused. Run it after the users were migrated, because owner_id and user_id
are foreign keys to users(id):

    python -m database.migrate_legacy_users
    python -m database.migrate_legacy_tables
"""
import sqlite3
from pathlib import Path

from database.config import PROJECT_ROOT, get_database_path
from database.init_db import init_database


LEGACY_FOLDER = PROJECT_ROOT / "database" / "data"
LEGACY_TABLES = {
    "assets": "assets.db",
    "threats": "threats.db",
    "notifications": "notifications.db",
}


def migrate_tables(source_folder=LEGACY_FOLDER, target_path=None):
    """Return {table: (copied, skipped)} for every old database that exists."""
    target_path = Path(target_path or get_database_path())
    init_database(database_path=target_path)
    target = sqlite3.connect(target_path)
    target.execute("PRAGMA foreign_keys = ON")

    results = {}
    try:
        for table, filename in LEGACY_TABLES.items():
            source_path = Path(source_folder) / filename
            if not source_path.exists():
                continue
            source = sqlite3.connect(source_path)
            source.row_factory = sqlite3.Row
            try:
                rows = source.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                counter = source.execute(
                    "SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)
                ).fetchone()
            finally:
                source.close()

            copied = skipped = 0
            for row in rows:
                columns = ", ".join(row.keys())
                placeholders = ", ".join("?" for _ in row.keys())
                try:
                    target.execute(
                        f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(row)
                    )
                    copied += 1
                except sqlite3.IntegrityError:
                    skipped += 1

            if counter is not None:
                target.execute(
                    "UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = ?", (counter[0], table)
                )
            results[table] = (copied, skipped)
        target.commit()
    except Exception:
        target.rollback()
        raise
    finally:
        target.close()

    return results


if __name__ == "__main__":
    for table_name, (copied, skipped) in migrate_tables().items():
        print(f"{table_name}: copied {copied}; already present or conflicting: {skipped}")
