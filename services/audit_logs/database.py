import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DATABASE = Path(__file__).resolve().parent / "audit_logs.db"


@contextmanager
def get_db(database_path=DEFAULT_DATABASE):
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db(database_path=DEFAULT_DATABASE):
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with get_db(database_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER CHECK(user_id IS NULL OR user_id > 0),
                action TEXT NOT NULL CHECK(length(trim(action)) BETWEEN 1 AND 100),
                description TEXT NOT NULL
                    CHECK(length(trim(description)) BETWEEN 1 AND 1000),
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                severity TEXT NOT NULL CHECK(
                    severity IN ('Information', 'Warning', 'Error', 'Critical')
                ),
                related_service TEXT NOT NULL
                    CHECK(length(trim(related_service)) BETWEEN 1 AND 100)
            );

            CREATE INDEX IF NOT EXISTS audit_logs_user
                ON audit_logs(user_id);
            CREATE INDEX IF NOT EXISTS audit_logs_timestamp
                ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS audit_logs_action
                ON audit_logs(action);

            CREATE TRIGGER IF NOT EXISTS audit_logs_are_immutable
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'Audit logs cannot be modified');
            END;
            """
        )


if __name__ == "__main__":
    init_db()
    print(f"Audit log database created: {DEFAULT_DATABASE}")
