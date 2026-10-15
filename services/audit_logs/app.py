"""
Service 5 - Security Audit Logging Service
Student: Chelsea Saydi

Run from the project root:
    python -m services.audit_logs.app
"""
import hmac
import os

from flask import Flask, current_app, g, jsonify, request

from services.audit_logs.auth import (
    ADMIN,
    ANALYST,
    AUDITOR,
    authenticate,
    error,
    require_roles,
)
from services.audit_logs.database import DEFAULT_DATABASE, init_db
from services.audit_logs.repository import AuditLogRepository
from services.audit_logs.validation import (
    positive_id,
    validate_create,
    validate_search,
)

ROUTE_PREFIX = "/chelsea-saydi"
SERVICE_NAME = "Security Audit Logging Service"


def success(data=None, message=None, status_code=200):
    body = {"status": "success"}
    if message:
        body["message"] = message
    if isinstance(data, list):
        body["count"] = len(data)
    if data is not None:
        body["data"] = data
    return jsonify(body), status_code


def repository():
    return AuditLogRepository(current_app.config["DATABASE_PATH"])


def create_app(database_path=None, internal_service_key=None):
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(database_path or DEFAULT_DATABASE)
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.config["INTERNAL_SERVICE_KEY"] = internal_service_key or os.environ.get(
        "INTERNAL_SERVICE_KEY", "dev-only-internal-service-key"
    )
    app.json.sort_keys = False
    init_db(app.config["DATABASE_PATH"])

    # 1. Create Log Record - Chelsea Saydi
    @app.post(ROUTE_PREFIX + "/logs")
    def create_log():
        supplied_key = request.headers.get("X-Service-Key", "")
        expected_key = current_app.config["INTERNAL_SERVICE_KEY"]
        internal_request = bool(supplied_key) and hmac.compare_digest(
            supplied_key, expected_key
        )
        if not internal_request:
            problem = authenticate((ADMIN,))
            if problem:
                return problem

        data, errors = validate_create(request.get_json(silent=True))
        if errors:
            return error("Validation failed", 400, errors)

        log = repository().create(data)
        return success(log, "Security log created successfully", 201)

    # 2. Retrieve All Logs - Chelsea Saydi
    @app.get(ROUTE_PREFIX + "/logs")
    @require_roles(ADMIN, AUDITOR)
    def get_logs():
        return success(repository().all())

    # 4. Search Logs - Chelsea Saydi
    @app.get(ROUTE_PREFIX + "/logs/search")
    @require_roles(ADMIN, AUDITOR, ANALYST)
    def search_logs():
        criteria, errors = validate_search(request.args)
        if errors:
            return error("Invalid search criteria", 400, errors)
        return success(repository().search(criteria))

    # 6. Retrieve Logs By User - Chelsea Saydi
    @app.get(ROUTE_PREFIX + "/logs/user/<int:user_id>")
    @require_roles(ADMIN, AUDITOR)
    def get_logs_by_user(user_id):
        problem = positive_id(user_id, "user_id")
        if problem:
            return error("Validation failed", 400, [problem])
        return success(repository().by_user(user_id))

    # 3. Retrieve Specific Log - Chelsea Saydi
    @app.get(ROUTE_PREFIX + "/logs/<int:log_id>")
    @require_roles(ADMIN, AUDITOR, ANALYST)
    def get_log(log_id):
        log = repository().get(log_id)
        if log is None:
            return error(f"Log with ID {log_id} not found", 404)
        return success(log)

    # 5. Delete Log - Chelsea Saydi
    @app.delete(ROUTE_PREFIX + "/logs/<int:log_id>")
    @require_roles(ADMIN)
    def delete_log(log_id):
        if not repository().delete(log_id):
            return error(f"Log with ID {log_id} not found", 404)
        repository().create(
            {
                "user_id": g.current_user["user_id"],
                "action": "AUDIT_LOG_DELETED",
                "description": f"Audit log {log_id} was deleted",
                "severity": "Warning",
                "related_service": SERVICE_NAME,
            }
        )
        return success(message=f"Log {log_id} deleted successfully")

    @app.errorhandler(404)
    def route_not_found(_exception):
        return error("The requested URL was not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(_exception):
        return error("This HTTP method is not allowed for this URL", 405)

    @app.errorhandler(500)
    def internal_error(_exception):
        return error("Internal server error", 500)

    return app


if __name__ == "__main__":
    port = int(os.environ.get("AUDIT_SERVICE_PORT", "5005"))
    create_app().run(host="127.0.0.1", port=port, debug=True)
