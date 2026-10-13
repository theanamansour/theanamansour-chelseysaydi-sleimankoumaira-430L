"""
Creates the shared SQLite database and every table found in database/schema/.

Run from the project root:
    python -m database.init_db

Schema files are applied in name order (01_..., 02_..., 04_...). Each file uses
CREATE TABLE IF NOT EXISTS, so running this again never deletes existing data.
"""
import sqlite3
from pathlib import Path

from shared import config

SCHEMA_FOLDER = Path(__file__).resolve().parent / "schema"


def init_database(database_path=config.DATABASE_PATH):
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        for schema_file in sorted(SCHEMA_FOLDER.glob("*.sql")):
            connection.executescript(schema_file.read_text())
            print(f"Applied {schema_file.name}")
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    init_database()
    print(f"Database ready: {config.DATABASE_PATH}")
