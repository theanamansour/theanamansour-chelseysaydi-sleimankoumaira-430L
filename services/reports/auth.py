"""Authentication and role checks for Service 6.

Every request is checked by Service 1 (POST /theana-mansour/auth/verify), so a
token is accepted only while its user still exists and is Active.
"""
import os
from functools import wraps

import requests
from flask import g, jsonify, request

from services.reports import audit_client

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"

USER_SERVICE_URL = os.environ.get(
    "USER_SERVICE_URL", "http://127.0.0.1:5001/theana-mansour"
)
VERIFY_TIMEOUT = float(os.environ.get("SERVICE_REQUEST_TIMEOUT", "3"))


def error(message, status_code, errors=None):
    body = {"status": "error", "message": message}
    if errors:
        body["errors"] = errors
    return jsonify(body), status_code


def verify_identity(authorization):
    """Ask Service 1 who owns the token.

    Returns (identity, None) on success or (None, error_response) on failure.
    """
    try:
        response = requests.post(
            f"{USER_SERVICE_URL}/auth/verify",
            headers={"Authorization": authorization},
            timeout=VERIFY_TIMEOUT,
        )
        payload = response.json() if response.content else {}
    except (requests.RequestException, ValueError):
        return None, error("User service is unavailable", 503)

    if response.status_code == 200 and payload.get("valid") is True:
        return payload, None
    if response.status_code == 401:
        return None, error(payload.get("message", "Invalid authentication token"), 401)
    return None, error("User service is unavailable", 503)


def require_roles(*allowed_roles):
    """Allow the route only for a valid token whose role is in allowed_roles."""
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                audit_client.send_audit_log(
                    None,
                    "UNAUTHENTICATED_ACCESS",
                    f"{request.method} {request.path} attempted without a token",
                    "Warning",
                )
                return error("Authentication token required", 401)

            identity, problem = verify_identity(authorization)
            if problem:
                if problem[1] == 401:
                    audit_client.send_audit_log(
                        None,
                        "UNAUTHENTICATED_ACCESS",
                        f"{request.method} {request.path} rejected: invalid token",
                        "Warning",
                    )
                return problem

            if identity["role"] not in allowed_roles:
                audit_client.send_audit_log(
                    identity["user_id"],
                    "PERMISSION_DENIED",
                    f"{identity['role']} attempted {request.method} {request.path}",
                    "Warning",
                )
                return error(
                    "User does not have permission to perform this operation", 403
                )

            g.current_user = identity
            return function(*args, **kwargs)
        return wrapper
    return decorator
