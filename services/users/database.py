
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DATABASE = Path(__file__).resolve().parent / "users.db"


@contextmanager
def get_db():
    connection = sqlite3.connect(DATABASE)
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


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                department TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Regular Employee',
                account_status TEXT NOT NULL DEFAULT 'Active',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_login_at TEXT
            )
        """)
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "users_username_nocase ON users(username COLLATE NOCASE)"
        )
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "users_email_nocase ON users(email COLLATE NOCASE)"
        )


if __name__ == "__main__":
    init_db()
    print("Users database created successfully.")
