"""
Service 7 - Vulnerability Management Service
Student: Theana Mansour

Registers vulnerabilities found on organisational assets, tracks their CVE,
CVSS score and severity, and enforces the remediation lifecycle
Open -> Under Investigation -> In Progress -> Resolved -> Closed.

Run from the project root:
    python -m services.vulnerabilities.app
"""
import os
import sqlite3

from flask import Flask, current_app, g, jsonify, request

from database.config import get_database_path
from database.init_db import init_database
from services.vulnerabilities import integrations
from services.vulnerabilities.auth import ADMIN, ANALYST, AUDITOR, error, require_roles
from services.vulnerabilities.repository import VulnerabilityRepository
from services.vulnerabilities.validation import (
    validate_create,
    validate_search,
    validate_update,
)

ROUTE_PREFIX = "/theana-mansour"
SERVICE_NAME = "Vulnerability Management Service"
ALERT_SEVERITIES = ("High", "Critical")
SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


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
    return VulnerabilityRepository(current_app.config["DATABASE_PATH"])


def alert_responders(vulnerability, reason):
    """Send a Vulnerability Alert (Service 8) to every active administrator and analyst."""
    asset = vulnerability["affected_asset"]["asset_name"] or f"asset {vulnerability['affected_asset_id']}"
    title = f"{vulnerability['severity']} vulnerability {vulnerability['cve_identifier']} on {asset}"
    message = (
        f"{vulnerability['vulnerability_title']} ({vulnerability['cve_identifier']}, "
        f"CVSS {vulnerability['cvss_score']}) {reason}. "
        f"Vulnerability ID {vulnerability['vulnerability_id']}, status {vulnerability['status']}."
    )
    sent = 0
    for user_id in repository().alert_recipients():
        if integrations.send_vulnerability_alert(user_id, title, message, vulnerability["severity"]):
            sent += 1
    return sent


def create_app(database_path=None):
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(database_path or get_database_path())
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False
    # Creates the vulnerabilities table (and the users and assets tables it
    # points to) if they do not exist yet. Never deletes data.
    init_database("vulnerabilities", app.config["DATABASE_PATH"])

    # 1. Add New Vulnerability - Theana Mansour
    @app.post(ROUTE_PREFIX + "/vulnerabilities")
    @require_roles(ADMIN)
    def add_vulnerability():
        data, errors = validate_create(request.get_json(silent=True))
        if errors:
            return error("Validation failed", 400, errors)

        if repository().asset(data["affected_asset_id"]) is None:
            return error("Validation failed", 400, [
                f"affected_asset_id {data['affected_asset_id']} does not match any registered asset"
            ])

        try:
            vulnerability = repository().create(data)
        except sqlite3.IntegrityError:
            return error(
                f"{data['cve_identifier']} is already recorded for asset {data['affected_asset_id']}",
                409,
            )

        user = g.current_user
        integrations.send_audit_log(
            user["user_id"],
            "CREATE_VULNERABILITY",
            f"Vulnerability {vulnerability['vulnerability_id']} ({vulnerability['cve_identifier']}, "
            f"{vulnerability['severity']}) was added for asset {vulnerability['affected_asset_id']}",
            "Warning" if vulnerability["severity"] == "Critical" else "Information",
        )
        if vulnerability["severity"] in ALERT_SEVERITIES:
            alert_responders(vulnerability, "was reported")
        return success(vulnerability, "Vulnerability created successfully", 201)

    # 2. Retrieve All Vulnerabilities - Theana Mansour
    @app.get(ROUTE_PREFIX + "/vulnerabilities")
    @require_roles(ADMIN, ANALYST, AUDITOR)
    def list_vulnerabilities():
        return success(repository().list_all())

    # 5. Search Vulnerabilities - Theana Mansour
    @app.get(ROUTE_PREFIX + "/vulnerabilities/search")
    @require_roles(ADMIN, ANALYST, AUDITOR)
    def search_vulnerabilities():
        filters, errors = validate_search(request.args)
        if errors:
            return error("Validation failed", 400, errors)
        return success(repository().search(filters))

    # 3. Retrieve Specific Vulnerability - Theana Mansour
    @app.get(ROUTE_PREFIX + "/vulnerabilities/<int:vulnerability_id>")
    @require_roles(ADMIN, ANALYST, AUDITOR)
    def get_vulnerability(vulnerability_id):
        vulnerability = repository().get(vulnerability_id)
        if vulnerability is None:
            return error("Vulnerability not found", 404)
        return success(vulnerability)

    # 4. Update Vulnerability Information - Theana Mansour
    @app.put(ROUTE_PREFIX + "/vulnerabilities/<int:vulnerability_id>")
    @require_roles(ADMIN, ANALYST)
    def update_vulnerability(vulnerability_id):
        current = repository().get(vulnerability_id)
        if current is None:
            return error("Vulnerability not found", 404)

        changes, errors = validate_update(request.get_json(silent=True), current)
        if errors:
            return error("Validation failed", 400, errors)

        updated = repository().update(vulnerability_id, changes)
        user = g.current_user
        described = ", ".join(
            f"status {current['status']} -> {updated['status']}" if field == "status" else field
            for field in changes
        )
        integrations.send_audit_log(
            user["user_id"],
            "UPDATE_VULNERABILITY",
            f"Vulnerability {vulnerability_id} updated: {described}",
        )
        if (
            updated["severity"] in ALERT_SEVERITIES
            and SEVERITY_RANK[updated["severity"]] > SEVERITY_RANK[current["severity"]]
        ):
            alert_responders(updated, f"was raised from {current['severity']} to {updated['severity']}")
        return success({"before": current, "after": updated}, "Vulnerability updated successfully")

    # 6. Delete Vulnerability - Theana Mansour
    @app.delete(ROUTE_PREFIX + "/vulnerabilities/<int:vulnerability_id>")
    @require_roles(ADMIN)
    def delete_vulnerability(vulnerability_id):
        vulnerability = repository().get(vulnerability_id)
        if vulnerability is None:
            return error("Vulnerability not found", 404)
        repository().delete(vulnerability_id)
        integrations.send_audit_log(
            g.current_user["user_id"],
            "DELETE_VULNERABILITY",
            f"Vulnerability {vulnerability_id} ({vulnerability['cve_identifier']}) was deleted",
            "Warning",
        )
        return success(message="Vulnerability deleted successfully")

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
    port = int(os.environ.get("VULNERABILITY_SERVICE_PORT", "5007"))
    create_app().run(host="127.0.0.1", port=port, debug=True)
