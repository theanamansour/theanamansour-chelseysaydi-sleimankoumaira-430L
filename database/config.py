import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "database" / "data" / "security_system.db"


def get_database_path():
    """Return the configured shared SQLite database path."""
    configured = os.environ.get("SYSTEM_DATABASE_PATH")
    if not configured:
        return DEFAULT_DATABASE_PATH

    path = Path(configured).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()
