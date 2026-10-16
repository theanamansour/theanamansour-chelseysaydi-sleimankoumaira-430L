"""
Authentication (who are you?) and authorization (are you allowed?) for Sleiman Koumaira's services.

Login belongs to Service 1 (Users and Identity Management, Theana Mansour):
    POST /theana-mansour/users/login         -> returns a signed token
    POST /theana-mansour/auth/verify         -> checks a token, returns the user's ID, username and role
Our services never read the token themselves. For every protected request they send the
caller's token to Service 1's verify endpoint and use the role it returns.
"""
import hmac
from functools import wraps

import requests
from flask import current_app, g, request

from shared import audit_client, config
from shared.responses import error_response

# The four roles, spelled exactly as Service 1 stores them.
ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
REGULAR_EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"
ALL_ROLES = (ADMIN, ANALYST, REGULAR_EMPLOYEE, AUDITOR)

# Identity used when another service calls us with the internal service key.
INTERNAL_SERVICE = "Internal Service"


class AuthServiceUnavailable(Exception):
    """Service 1 could not be reached, so nobody can be authenticated."""


def verify_token(authorization_header):
    """
    Ask Service 1 who owns this token.
    Returns (user, None) on success, where user is {"user_id", "username", "role"},
    or (None, message) when Service 1 rejects the token (invalid, expired, inactive account).
    Raises AuthServiceUnavailable if Service 1 does not answer.
    """
    try:
        response = requests.post(
            config.AUTH_VERIFY_URL,
            headers={"Authorization": authorization_header},
            timeout=config.REQUEST_TIMEOUT,
        )
        body = response.json()
    except (requests.RequestException, ValueError) as problem:
        raise AuthServiceUnavailable() from problem

    if response.status_code == 200 and body.get("valid") is True:
        return {"user_id": body["user_id"], "username": body["username"], "role": body["role"]}, None
    return None, body.get("message", "Invalid token")


def has_valid_service_key():
    """True if the request carries the correct X-Service-Key header (service-to-service call)."""
    sent_key = request.headers.get("X-Service-Key", "")
    # compare_digest takes the same time whether the keys match or not (no timing hints).
    return bool(sent_key) and hmac.compare_digest(sent_key, config.internal_service_key())


def require_roles(*allowed_roles, allow_service_key=False):
    """
    Decorator placed on a route: only users whose role is in allowed_roles may call it.

    401 -> no token, or Service 1 says the token is invalid/expired/inactive (we do not know who you are)
    403 -> valid token, but the role is not allowed (we know who you are, but you may not)
    503 -> Service 1 is down, so we cannot check who you are
    With allow_service_key=True, another service may call the route with the X-Service-Key header.
    """

    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):
            service_name = current_app.config["SERVICE_NAME"]
            attempted = f"{request.method} {request.path}"

            if allow_service_key and has_valid_service_key():
                g.current_user = {"user_id": None, "username": "internal-service", "role": INTERNAL_SERVICE}
                g.authorization_header = None
                return view_function(*args, **kwargs)

            header = request.headers.get("Authorization", "")
            scheme, _, token = header.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                _log_access_problem(None, "UNAUTHENTICATED_ACCESS", f"{attempted} without a token", service_name)
                return error_response("Authentication required: send 'Authorization: Bearer <token>'", 401)

            try:
                user, problem = verify_token(header)
            except AuthServiceUnavailable:
                return error_response("Authentication service (Service 1) is unavailable, try again later", 503)

            if user is None:
                _log_access_problem(None, "UNAUTHENTICATED_ACCESS", f"{attempted} rejected: {problem}", service_name)
                return error_response(problem, 401)

            if user["role"] not in allowed_roles:
                _log_access_problem(
                    user["user_id"],
                    "PERMISSION_DENIED",
                    f"{user['role']} '{user['username']}' attempted {attempted}",
                    service_name,
                )
                return error_response("User does not have permission to perform this operation", 403)

            # Save the caller so the route can use it, e.g. g.current_user["user_id"].
            g.current_user = user
            g.authorization_header = header
            return view_function(*args, **kwargs)

        return wrapper

    return decorator


def _log_access_problem(user_id, action, description, service_name):
    """Unauthorized access attempts must be recorded in the Security Audit Logging Service."""
    audit_client.send_audit_log(
        user_id=user_id,
        action=action,
        description=description,
        severity="Warning",
        related_service=service_name,
    )
