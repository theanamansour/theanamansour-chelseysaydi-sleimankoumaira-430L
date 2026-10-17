"""Best-effort client for Service 5 security audit logging."""
import os
import secrets
from pathlib import Path

import requests


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUDIT_LOG_URL = os.environ.get(
    "AUDIT_LOG_URL", "http://127.0.0.1:5005/chelsea-saydi/logs"
)
REQUEST_TIMEOUT = float(os.environ.get("SERVICE_REQUEST_TIMEOUT", "1"))


def _internal_service_key():
    configured = os.environ.get("INTERNAL_SERVICE_KEY")
    if configured:
        return configured

    key_file = PROJECT_ROOT / ".internal_service_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    return key_file.read_text().strip()


def send_audit_log(
    user_id,
    action,
    description,
    severity="Information",
):
    """Send an audit event without making the user operation depend on Service 5."""
    if os.environ.get("AUDIT_LOG_DISABLED") == "1":
        return False

    try:
        response = requests.post(
            AUDIT_LOG_URL,
            json={
                "user_id": user_id,
                "action": action,
                "description": description,
                "severity": severity,
                "related_service": "Users and Identity Management Service",
            },
            headers={"X-Service-Key": _internal_service_key()},
            timeout=REQUEST_TIMEOUT,
        )
        return response.status_code == 201
    except requests.RequestException:
        return False
