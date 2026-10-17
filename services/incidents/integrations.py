import logging
import os

import requests

from shared import config, notification_client

USER_SERVICE_URL = os.environ.get(
    "USER_SERVICE_URL", "http://127.0.0.1:5001/theana-mansour"
)
AUDIT_SERVICE_URL = os.environ.get(
    "AUDIT_SERVICE_URL", "http://127.0.0.1:5005/chelsea-saydi/logs"
)

logger = logging.getLogger(__name__)


class ServiceUnavailable(Exception):
    """Raised when a required peer service cannot be contacted."""


def _authorization_headers(authorization):
    return {"Authorization": authorization}


def verify_identity(authorization):
    try:
        response = requests.post(
            f"{USER_SERVICE_URL}/auth/verify",
            headers=_authorization_headers(authorization),
            timeout=3,
        )
    except requests.RequestException as exc:
        raise ServiceUnavailable("User service is unavailable") from exc

    payload = response.json() if response.content else {}
    if response.status_code != 200 or not payload.get("valid"):
        return None, payload.get("message", "Invalid authentication token")
    return payload, None


def get_user(user_id, authorization):
    """Use Service 1's authorized user listing to validate a user and role."""
    try:
        response = requests.get(
            f"{USER_SERVICE_URL}/users",
            headers=_authorization_headers(authorization),
            timeout=3,
        )
    except requests.RequestException as exc:
        raise ServiceUnavailable("User service is unavailable") from exc

    if response.status_code != 200:
        raise ServiceUnavailable("User service rejected the lookup")

    users = response.json()
    if isinstance(users, dict):
        users = users.get("data", [])
    return next((user for user in users if user.get("id") == user_id), None)


def notify_assigned_analyst(incident):
    """Ask Service 8 to tell the analyst about the assignment; never fails the assignment."""
    notification_client.send_notification(
        user_id=incident["assigned_analyst_id"],
        title="Incident assigned",
        message=(
            f"Incident {incident['incident_id']}: {incident['title']} "
            "has been assigned to you."
        ),
        notification_type="Incident Assignment",
        severity=incident["severity"],
    )


def send_audit_log(user_id, action, description, severity="Information"):
    """Audit failures are logged locally and never roll back the primary operation."""
    try:
        response = requests.post(
            AUDIT_SERVICE_URL,
            json={
                "user_id": user_id,
                "action": action,
                "description": description,
                "severity": severity,
                "related_service": "Incident Management Service",
            },
            headers={"X-Service-Key": config.internal_service_key()},
            timeout=2,
        )
        if response.status_code >= 400:
            logger.warning("Audit service rejected event %s", action)
    except requests.RequestException:
        logger.warning("Audit service unavailable; event not saved: %s", action)
