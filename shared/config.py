"""
Settings shared by Sleiman Koumaira's services.

Each value can be overridden with an environment variable. Secrets are never written
in the code: they come from environment variables or from local files that Git ignores.
"""
import os
import secrets
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FOLDER = PROJECT_ROOT / "database" / "data"

# Every service keeps its own SQLite database (the team's design: one database per service).
DATABASE_PATHS = {
    "threats": os.environ.get("THREATS_DATABASE_PATH", str(DATA_FOLDER / "threats.db")),
}

# Port of each service. 5000 is skipped because macOS uses it for AirPlay Receiver.
SERVICE_PORTS = {
    "users": 5001,
    "assets": 5002,
    "incidents": 5003,
    "threats": 5004,
    "audit_logs": 5005,
    "reports": 5006,
    "vulnerabilities": 5007,
    "notifications": 5008,
    "playbooks": 5009,
}

# Service 1 - Users and Identity Management (Theana Mansour).
USERS_SERVICE_URL = os.environ.get("USERS_SERVICE_URL", f"http://127.0.0.1:{SERVICE_PORTS['users']}")
AUTH_VERIFY_URL = f"{USERS_SERVICE_URL}/theana-mansour/auth/verify"
USERS_LIST_URL = f"{USERS_SERVICE_URL}/theana-mansour/users"

# Service 8 - Notification and Alert Management (Sleiman Koumaira).
NOTIFICATIONS_URL = os.environ.get(
    "NOTIFICATIONS_URL", f"http://127.0.0.1:{SERVICE_PORTS['notifications']}/sleiman-koumaira/notifications"
)

# Service 5 - Security Audit Logging: the internal route for automatic log records.
# The exact path is finalised when Service 5 is implemented; override it with AUDIT_LOG_URL.
AUDIT_LOG_URL = os.environ.get("AUDIT_LOG_URL", f"http://127.0.0.1:{SERVICE_PORTS['audit_logs']}/logs")

# How long (seconds) to wait for another service before giving up.
REQUEST_TIMEOUT = 3


def _load_internal_service_key():
    """
    The secret that services send to each other in the X-Service-Key header.
    Taken from the INTERNAL_SERVICE_KEY environment variable, or else from the local file
    .internal_service_key (ignored by Git), which is created on first use.
    """
    if os.environ.get("INTERNAL_SERVICE_KEY"):
        return os.environ["INTERNAL_SERVICE_KEY"]
    key_file = PROJECT_ROOT / ".internal_service_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    return key_file.read_text().strip()


INTERNAL_SERVICE_KEY = _load_internal_service_key()
