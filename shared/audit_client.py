"""
Sends audit log records to the Security Audit Logging Service (Service 5).

Service 5 is built by a teammate. Until it is running, the request fails and we
print a warning instead of crashing, so our own APIs keep working.
"""
import logging

import requests

from shared import config

logger = logging.getLogger("audit_client")


def send_audit_log(user_id, action, description, severity, related_service):
    """
    POST one log record to Service 5.

    severity must be one of: Information, Warning, Error, Critical.
    user_id can be None when we do not know who the caller is (e.g. missing token).
    """
    log_record = {
        "user_id": user_id,
        "action": action,
        "description": description,
        "severity": severity,
        "related_service": related_service,
    }
    try:
        response = requests.post(
            config.AUDIT_LOG_URL,
            json=log_record,
            headers={"X-Service-Key": config.internal_service_key()},
            timeout=2,
        )
        if response.status_code >= 400:
            logger.warning("Audit service rejected log (%s): %s", response.status_code, log_record)
    except requests.RequestException:
        logger.warning("Audit service unreachable, log not saved: %s", log_record)
