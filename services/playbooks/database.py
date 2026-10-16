import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DATABASE = Path(__file__).resolve().parent / "playbooks.db"


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
            CREATE TABLE IF NOT EXISTS playbooks (
                playbook_id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_name TEXT NOT NULL
                    CHECK(length(trim(playbook_name)) BETWEEN 1 AND 150),
                description TEXT NOT NULL
                    CHECK(length(trim(description)) BETWEEN 1 AND 2000),
                incident_category TEXT NOT NULL
                    CHECK(length(trim(incident_category)) BETWEEN 1 AND 100),
                severity TEXT NOT NULL
                    CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
                created_by INTEGER NOT NULL CHECK(created_by > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS response_actions (
                action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id INTEGER NOT NULL,
                action_description TEXT NOT NULL
                    CHECK(length(trim(action_description)) BETWEEN 1 AND 1000),
                step_number INTEGER NOT NULL CHECK(step_number > 0),
                status TEXT NOT NULL DEFAULT 'Pending'
                    CHECK(status IN ('Pending', 'In Progress', 'Completed')),
                assigned_user_id INTEGER CHECK(assigned_user_id > 0),
                completion_date TEXT,
                FOREIGN KEY (playbook_id) REFERENCES playbooks(playbook_id)
                    ON DELETE CASCADE,
                UNIQUE(playbook_id, step_number)
            );

            CREATE TABLE IF NOT EXISTS response_action_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id INTEGER NOT NULL,
                previous_status TEXT,
                new_status TEXT NOT NULL,
                changed_by INTEGER NOT NULL CHECK(changed_by > 0),
                assigned_user_id INTEGER,
                changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (action_id) REFERENCES response_actions(action_id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS actions_playbook
                ON response_actions(playbook_id, step_number);
            CREATE INDEX IF NOT EXISTS history_action
                ON response_action_history(action_id, history_id);
            """
        )


if __name__ == "__main__":
    init_db()
    print(f"Playbook database created: {DEFAULT_DATABASE}")
