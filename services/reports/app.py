"""
Service 6 - Security Reports Service
Student: Theana Mansour

Builds read-only security reports from the shared database for
Security Administrators and Auditors.

Run from the project root:
    python -m services.reports.app
"""
import os
from datetime import datetime, timezone

from flask import Flask, current_app, g, jsonify, request

from database.config import get_database_path
from database.init_db import init_database
from services.reports import audit_client
from services.reports.auth import ADMIN, AUDITOR, error, require_roles
from services.reports.repository import ReportRepository

ROUTE_PREFIX = "/theana-mansour/reports"
SERVICE_NAME = "Security Reports Service"
DEFAULT_LIMIT = 5
MAX_LIMIT = 50
REPORT_ROLES = (ADMIN, AUDITOR)


def read_limit():
    """Validate the optional ?limit= query parameter used for the recent lists.

    Returns (limit, None) or (None, error_response).
    """
    unknown = sorted(set(request.args) - {"limit"})
    if unknown:
        return None, error(
            "Validation failed", 400,
            [f"Unknown query parameter(s): {', '.join(unknown)}"],
        )

    raw = request.args.get("limit")
    if raw is None:
        return DEFAULT_LIMIT, None
    if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= MAX_LIMIT:
        return None, error(
            "Validation failed", 400,
            [f"limit must be a whole number between 1 and {MAX_LIMIT}"],
        )
    return int(raw), None


def report_response(name, title, data):
    user = g.current_user
    audit_client.send_audit_log(
        user["user_id"],
        "GENERATE_REPORT",
        f"{user['username']} ({user['role']}) generated the {name} report",
    )
    return jsonify({
        "status": "success",
        "message": f"{title} generated successfully",
        "report": name,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "generated_by": {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
        },
        "data": data,
    }), 200


def create_app(database_path=None):
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(database_path or get_database_path())
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False
    # Make sure every table the reports read exists (never deletes data).
    init_database(database_path=app.config["DATABASE_PATH"])

    def repository():
        return ReportRepository(current_app.config["DATABASE_PATH"])

    def build(name, title, method_name):
        limit, problem = read_limit()
        if problem:
            return problem
        data = getattr(repository(), method_name)(limit)
        return report_response(name, title, data)

    # 1. Generate Security Summary Report - Theana Mansour
    @app.get(ROUTE_PREFIX + "/summary")
    @require_roles(*REPORT_ROLES)
    def summary_report():
        return build("summary", "Security summary report", "summary")

    # 2. Generate Incident Report - Theana Mansour
    @app.get(ROUTE_PREFIX + "/incidents")
    @require_roles(*REPORT_ROLES)
    def incident_report():
        return build("incidents", "Incident report", "incidents")

    # 3. Generate Asset Report - Theana Mansour
    @app.get(ROUTE_PREFIX + "/assets")
    @require_roles(*REPORT_ROLES)
    def asset_report():
        return build("assets", "Asset report", "assets")

    # 4. Generate Threat Report - Theana Mansour
    @app.get(ROUTE_PREFIX + "/threats")
    @require_roles(*REPORT_ROLES)
    def threat_report():
        return build("threats", "Threat report", "threats")

    # 5. Generate Vulnerability Report - Theana Mansour
    @app.get(ROUTE_PREFIX + "/vulnerabilities")
    @require_roles(*REPORT_ROLES)
    def vulnerability_report():
        return build("vulnerabilities", "Vulnerability report", "vulnerabilities")

    # 6. Generate Activity Report - Theana Mansour
    @app.get(ROUTE_PREFIX + "/activity")
    @require_roles(*REPORT_ROLES)
    def activity_report():
        return build("activity", "Activity report", "activity")

    @app.errorhandler(404)
    def not_found(_exception):
        return error("Resource not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(_exception):
        return error("Method not allowed", 405)

    @app.errorhandler(500)
    def internal_error(_exception):
        return error("Internal server error", 500)

    return app


if __name__ == "__main__":
    port = int(os.environ.get("REPORTS_SERVICE_PORT", "5006"))
    create_app().run(host="127.0.0.1", port=port, debug=True)
