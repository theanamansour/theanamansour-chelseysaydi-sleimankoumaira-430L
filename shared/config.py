"""
Settings shared by every service.

Each value can be overridden with an environment variable, so real secrets never
have to be written in the code. The defaults below are for local development only.
"""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# One SQLite file shared by all nine services, so tables can use foreign keys
# (for example assets.owner_id -> users.user_id).
DATABASE_PATH = os.environ.get(
    "DATABASE_PATH", str(PROJECT_ROOT / "database" / "data" / "security_system.db")
)

# Secret used to sign and verify login tokens (JWT).
# Service 1 signs the token at login; every other service verifies it with the same secret.
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-jwt-secret-do-not-use-in-production")
JWT_ALGORITHM = "HS256"

# Secret that services send to each other for internal calls (e.g. writing audit logs).
INTERNAL_SERVICE_KEY = os.environ.get("INTERNAL_SERVICE_KEY", "dev-only-internal-service-key")

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

# Full URL of Service 5's "Create Log Record" endpoint (POST /logs).
AUDIT_LOG_URL = os.environ.get(
    "AUDIT_LOG_URL", f"http://127.0.0.1:{SERVICE_PORTS['audit_logs']}/logs"
)
