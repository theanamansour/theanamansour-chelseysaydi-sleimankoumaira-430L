"""
Creates notifications in Service 8 (Notification and Alert Management, Sleiman Koumaira)
on behalf of another service, using the internal X-Service-Key header.
"""
import logging

import requests

from shared import config

logger = logging.getLogger("notification_client")


def send_notification(user_id, title, message, notification_type, severity):
    """POST one notification to Service 8. Returns True if it was created."""
    notification = {
        "user_id": user_id,
        "title": title,
        "message": message,
        "notification_type": notification_type,
        "severity": severity,
    }
    try:
        response = requests.post(
            config.NOTIFICATIONS_URL,
            json=notification,
            headers={"X-Service-Key": config.internal_service_key()},
            timeout=config.REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        logger.warning("Notification service unreachable, notification not created: %s", notification)
        return False

    if response.status_code != 201:
        logger.warning("Notification service rejected notification (%s): %s", response.status_code, notification)
        return False
    return True
