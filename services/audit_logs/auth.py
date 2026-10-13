import os
from functools import wraps

import requests
from flask import current_app, g, jsonify, request

from services.audit_logs.repository import AuditLogRepository

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"

USER_SERVICE_URL = os.environ.get(
    "USER_SERVICE_URL", "http://127.0.0.1:5001/theana-mansour"
)


def error(message, status_code, errors=None):
    body = {"status": "error", "message": message}
    if errors:
        body["errors"] = errors
    return jsonify(body), status_code


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


def record_denial(user_id, action, description):
    AuditLogRepository(current_app.config["DATABASE_PATH"]).create(
        {
            "user_id": user_id,
            "action": action,
            "description": description,
            "severity": "Warning",
            "related_service": "Security Audit Logging Service",
        }
    )


def authenticate(allowed_roles):
    authorization = request.headers.get("Authorization", "")
    if not authorization.lower().startswith("bearer "):
        record_denial(
            None,
            "UNAUTHENTICATED_ACCESS",
            f"{request.method} {request.path} attempted without a token",
        )
        return error("Authentication token required", 401)

    identity, problem = verify_identity(authorization)
    if problem:
        return problem
    if identity["role"] not in allowed_roles:
        record_denial(
            identity["user_id"],
            "PERMISSION_DENIED",
            f"{identity['role']} attempted {request.method} {request.path}",
        )
        return error(
            "User does not have permission to perform this operation", 403
        )

    g.current_user = identity
    return None


def require_roles(*allowed_roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            problem = authenticate(allowed_roles)
            if problem:
                return problem
            return function(*args, **kwargs)

        return wrapper

    return decorator
