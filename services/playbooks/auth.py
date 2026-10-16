import os
from functools import wraps

import requests
from flask import g, jsonify, request

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"

USER_SERVICE_URL = os.environ.get(
    "USER_SERVICE_URL", "http://127.0.0.1:5001/theana-mansour"
)
AUDIT_SERVICE_URL = os.environ.get(
    "AUDIT_SERVICE_URL", "http://127.0.0.1:5005/chelsea-saydi/logs"
)
INTERNAL_SERVICE_KEY = os.environ.get(
    "INTERNAL_SERVICE_KEY", "dev-only-internal-service-key"
)


def error(message, status_code, errors=None):
    body = {"status": "error", "message": message}
    if errors:
        body["errors"] = errors
    return jsonify(body), status_code


def send_audit_log(user_id, action, description, severity="Information"):
    try:
        requests.post(
            AUDIT_SERVICE_URL,
            json={
                "user_id": user_id,
                "action": action,
                "description": description,
                "severity": severity,
                "related_service": "Security Playbook and Response Service",
            },
            headers={"X-Service-Key": INTERNAL_SERVICE_KEY},
            timeout=2,
        )
    except requests.RequestException:
        pass


def verify_identity(authorization):
    try:
        response = requests.post(
            f"{USER_SERVICE_URL}/auth/verify",
            headers={"Authorization": authorization},
            timeout=3,
        )
        payload = response.json() if response.content else {}
    except (requests.RequestException, ValueError):
        return None, error("User service is unavailable", 503)

    if response.status_code != 200 or not payload.get("valid"):
        return None, error(
            payload.get("message", "Invalid authentication token"), 401
        )
    return payload, None


def require_roles(*allowed_roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            if not authorization.lower().startswith("bearer "):
                send_audit_log(
                    None,
                    "UNAUTHENTICATED_ACCESS",
                    f"{request.method} {request.path} attempted without a token",
                    "Warning",
                )
                return error("Authentication token required", 401)

            identity, problem = verify_identity(authorization)
            if problem:
                return problem
            if identity["role"] not in allowed_roles:
                send_audit_log(
                    identity["user_id"],
                    "PERMISSION_DENIED",
                    f"{identity['role']} attempted "
                    f"{request.method} {request.path}",
                    "Warning",
                )
                return error(
                    "User does not have permission to perform this operation",
                    403,
                )

            g.current_user = identity
            return function(*args, **kwargs)

        return wrapper

    return decorator
