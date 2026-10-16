"""Create every table in the team's shared SQLite database."""
from pathlib import Path

from database.config import get_database_path
from database.connection import get_db


SCHEMA_FOLDER = Path(__file__).resolve().parent / "schema"
SCHEMA_FILES = (
    "01_users.sql",
    "02_assets.sql",
    "03_incidents.sql",
    "04_threats.sql",
    "05_audit_logs.sql",
    "07_vulnerabilities.sql",
    "08_notifications.sql",
    "09_playbooks.sql",
)

SERVICE_SCHEMAS = {
    "users": ("01_users.sql",),
    "assets": ("01_users.sql", "02_assets.sql"),
    "incidents": ("01_users.sql", "02_assets.sql", "03_incidents.sql"),
    "threats": ("04_threats.sql",),
    "audit_logs": ("01_users.sql", "05_audit_logs.sql"),
    "vulnerabilities": (
        "01_users.sql",
        "02_assets.sql",
        "07_vulnerabilities.sql",
    ),
    "notifications": ("01_users.sql", "08_notifications.sql"),
    "playbooks": ("01_users.sql", "09_playbooks.sql"),
}


def init_database(service=None, database_path=None):
    """Create all tables, or one service and its dependency tables."""
    if service is not None and service not in SERVICE_SCHEMAS:
        raise ValueError(f"Unknown service: {service}")

    path = database_path or get_database_path()
    filenames = SERVICE_SCHEMAS[service] if service else SCHEMA_FILES
    with get_db(path) as connection:
        for filename in filenames:
            connection.executescript((SCHEMA_FOLDER / filename).read_text())
    return path


if __name__ == "__main__":
    created_path = init_database()
    print(f"Shared database initialized: {created_path}")
