"""Copy existing Service 1 users into the shared database without deleting data."""
import sqlite3
from pathlib import Path

from database.config import PROJECT_ROOT, get_database_path
from database.init_db import init_database


LEGACY_DATABASE = PROJECT_ROOT / "services" / "users" / "users.db"
USER_COLUMNS = (
    "id",
    "full_name",
    "username",
    "email",
    "password_hash",
    "department",
    "role",
    "account_status",
    "created_at",
    "last_login_at",
)


def migrate_users(source_path=LEGACY_DATABASE, target_path=None):
    source_path = Path(source_path)
    target_path = Path(target_path or get_database_path())

    if not source_path.exists():
        return 0, 0

    init_database(database_path=target_path)
    source = sqlite3.connect(source_path)
    source.row_factory = sqlite3.Row
    target = sqlite3.connect(target_path)
    target.execute("PRAGMA foreign_keys = ON")

    migrated = 0
    skipped = 0
    placeholders = ", ".join("?" for _ in USER_COLUMNS)
    column_list = ", ".join(USER_COLUMNS)

    try:
        users = source.execute(
            f"SELECT {column_list} FROM users ORDER BY id"
        ).fetchall()
        for user in users:
            try:
                target.execute(
                    f"INSERT INTO users ({column_list}) VALUES ({placeholders})",
                    tuple(user[column] for column in USER_COLUMNS),
                )
                migrated += 1
            except sqlite3.IntegrityError:
                skipped += 1
        target.commit()
    except Exception:
        target.rollback()
        raise
    finally:
        source.close()
        target.close()

    return migrated, skipped


if __name__ == "__main__":
    copied, unchanged = migrate_users()
    print(f"Legacy users copied: {copied}; already present or conflicting: {unchanged}")
