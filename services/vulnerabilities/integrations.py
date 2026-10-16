"""Best-effort calls from Service 7 to Service 5 (audit logs) and Service 8 (notifications).

Neither call can break a vulnerability operation: failures are ignored and the
functions simply return False.
"""
import os
import secrets
from pathlib import Path

import requests


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUDIT_LOG_URL = os.environ.get(
    "AUDIT_LOG_URL", "http://127.0.0.1:5005/chelsea-saydi/logs"
)
NOTIFICATIONS_URL = os.environ.get(
    "NOTIFICATIONS_URL", "http://127.0.0.1:5008/sleiman-koumaira/notifications"
)
REQUEST_TIMEOUT = float(os.environ.get("SERVICE_REQUEST_TIMEOUT", "1"))
RELATED_SERVICE = "Vulnerability Management Service"


def _internal_service_key():
    configured = os.environ.get("INTERNAL_SERVICE_KEY")
    if configured:
        return configured

    key_file = PROJECT_ROOT / ".internal_service_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    return key_file.read_text().strip()


def send_audit_log(user_id, action, description, severity="Information"):
    """Record an event in Service 5."""
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
                "related_service": RELATED_SERVICE,
            },
            headers={"X-Service-Key": _internal_service_key()},
            timeout=REQUEST_TIMEOUT,
        )
        return response.status_code == 201
    except requests.RequestException:
        return False


def send_vulnerability_alert(user_id, title, message, severity):
    """Send a "Vulnerability Alert" notification to one user through Service 8."""
    if os.environ.get("NOTIFICATIONS_DISABLED") == "1":
        return False

    try:
        response = requests.post(
            NOTIFICATIONS_URL,
            json={
                "user_id": user_id,
                "title": title[:150],
                "message": message[:1000],
                "notification_type": "Vulnerability Alert",
                "severity": severity,
            },
            headers={"X-Service-Key": _internal_service_key()},
            timeout=REQUEST_TIMEOUT,
        )
        return response.status_code == 201
    except requests.RequestException:
        return False
