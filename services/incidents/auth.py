from functools import wraps

from flask import g, request

from services.incidents import integrations

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"


def error(message, status_code, errors=None):
    from flask import jsonify

    body = {"status": "error", "message": message}
    if errors:
        body["errors"] = errors
    return jsonify(body), status_code


def require_roles(*allowed_roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            if not authorization.lower().startswith("bearer "):
                integrations.send_audit_log(
                    None,
                    "UNAUTHENTICATED_ACCESS",
                    f"{request.method} {request.path} without a token",
                    "Warning",
                )
                return error("Authentication token required", 401)

            try:
                identity, problem = integrations.verify_identity(authorization)
            except integrations.ServiceUnavailable as exc:
                return error(str(exc), 503)

            if problem:
                return error(problem, 401)
            if identity["role"] not in allowed_roles:
                integrations.send_audit_log(
                    identity["user_id"],
                    "PERMISSION_DENIED",
                    f"{identity['role']} attempted {request.method} {request.path}",
                    "Warning",
                )
                return error(
                    "User does not have permission to perform this operation", 403
                )

            g.current_user = identity
            g.authorization = authorization
            return function(*args, **kwargs)

        return wrapper

    return decorator
