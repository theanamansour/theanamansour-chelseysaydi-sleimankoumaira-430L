"""
Creates the SQLite database of each of Sleiman Koumaira's services.

Every service has its own database file (the team's design), built from its schema file
in database/schema/. Run from the project root:
    python -m database.init_db

Each schema uses CREATE TABLE IF NOT EXISTS, so running this again never deletes data.
"""
import sqlite3
from pathlib import Path

from shared import config

SCHEMA_FOLDER = Path(__file__).resolve().parent / "schema"

# Which schema file builds which service's database.
SERVICE_SCHEMAS = {
    "threats": "04_threats.sql",
}


def init_database(service, database_path=None):
    """Create (or update) the database of one service. Tests pass their own database_path."""
    database_path = database_path or config.DATABASE_PATHS[service]
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript((SCHEMA_FOLDER / SERVICE_SCHEMAS[service]).read_text())
        connection.commit()
    finally:
        connection.close()
    return database_path


if __name__ == "__main__":
    for service_name in SERVICE_SCHEMAS:
        path = init_database(service_name)
        print(f"{service_name}: {path}")
