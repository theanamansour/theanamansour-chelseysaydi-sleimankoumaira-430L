import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DATABASE = Path(__file__).resolve().parent / "incidents.db"


@contextmanager
def get_db(database_path=DEFAULT_DATABASE):
    connection = sqlite3.connect(database_path)
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


def init_db(database_path=DEFAULT_DATABASE):
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with get_db(database_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 150),
                description TEXT NOT NULL CHECK(length(trim(description)) BETWEEN 1 AND 2000),
                category TEXT NOT NULL CHECK(length(trim(category)) BETWEEN 1 AND 100),
                severity TEXT NOT NULL
                    CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
                reporter_id INTEGER NOT NULL CHECK(reporter_id > 0),
                asset_id INTEGER NOT NULL CHECK(asset_id > 0),
                assigned_analyst_id INTEGER CHECK(assigned_analyst_id > 0),
                status TEXT NOT NULL DEFAULT 'Open'
                    CHECK(status IN (
                        'Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed'
                    )),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                resolution_date TEXT
            );

            CREATE TABLE IF NOT EXISTS investigation_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                analyst_id INTEGER NOT NULL CHECK(analyst_id > 0),
                note_content TEXT NOT NULL
                    CHECK(length(trim(note_content)) BETWEEN 1 AND 2000),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS incidents_reporter
                ON incidents(reporter_id);
            CREATE INDEX IF NOT EXISTS incidents_assigned_analyst
                ON incidents(assigned_analyst_id);
            CREATE INDEX IF NOT EXISTS notes_incident
                ON investigation_notes(incident_id);
            """
        )


if __name__ == "__main__":
    init_db()
    print(f"Incident database created: {DEFAULT_DATABASE}")
