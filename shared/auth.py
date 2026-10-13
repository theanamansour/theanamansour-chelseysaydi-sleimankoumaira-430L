"""
Authentication (who are you?) and authorization (are you allowed?) for every service.

Login itself belongs to Service 1: POST /users/login checks the password and returns
a token made by create_access_token(). Every other service only verifies that token.
"""
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, request

from shared import audit_client, config
from shared.responses import error_response

# The four roles, spelled exactly as Service 1 (Users and Identity) stores them.
ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
REGULAR_EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"
ALL_ROLES = (ADMIN, ANALYST, REGULAR_EMPLOYEE, AUDITOR)


def create_access_token(user_id, username, role, expires_in_minutes=60):
    """Create a signed token that proves who the user is and what role they have."""
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "iat": now,  # issued at
        "exp": now + timedelta(minutes=expires_in_minutes),  # expires at
    }
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)


def decode_access_token(token):
    """Check the signature and expiry date. Raises jwt.InvalidTokenError if anything is wrong."""
    return jwt.decode(
        token,
        config.JWT_SECRET_KEY,
        algorithms=[config.JWT_ALGORITHM],
        options={"require": ["exp", "user_id", "role"]},
    )


def require_roles(*allowed_roles):
    """
    Decorator placed on a route: only users whose role is in allowed_roles may call it.

    401 -> no token, or the token is invalid/expired (we do not know who you are)
    403 -> valid token, but the role is not allowed (we know who you are, but you may not)
    """

    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):
            service_name = current_app.config["SERVICE_NAME"]
            attempted = f"{request.method} {request.path}"

            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                _log_access_problem(None, "UNAUTHENTICATED_ACCESS", f"{attempted} without a token", service_name)
                return error_response(
                    "Authentication required: send 'Authorization: Bearer <token>'", 401
                )

            try:
                user = decode_access_token(header[len("Bearer "):].strip())
            except jwt.ExpiredSignatureError:
                _log_access_problem(None, "UNAUTHENTICATED_ACCESS", f"{attempted} with an expired token", service_name)
                return error_response("Token has expired, please log in again", 401)
            except jwt.InvalidTokenError:
                _log_access_problem(None, "UNAUTHENTICATED_ACCESS", f"{attempted} with an invalid token", service_name)
                return error_response("Invalid authentication token", 401)

            if user["role"] not in allowed_roles:
                _log_access_problem(
                    user["user_id"],
                    "PERMISSION_DENIED",
                    f"{user['role']} '{user.get('username')}' attempted {attempted}",
                    service_name,
                )
                return error_response("User does not have permission to perform this operation", 403)

            # Save the caller so the route can use it (e.g. g.current_user["user_id"]).
            g.current_user = user
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
