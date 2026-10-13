"""
Service 4 - Threat Intelligence Service
Owner: Sleiman Koumaira

Run from the project root:
    python -m services.threats.app
The service listens on http://127.0.0.1:5004/sleiman-koumaira/threats
"""
import sqlite3
from pathlib import Path

from flask import Blueprint, Flask, current_app, g, request

from services.threats.repository import ThreatRepository
from services.threats.validation import (
    validate_new_threat,
    validate_search_criteria,
    validate_threat_update,
)
from shared import audit_client, config, notification_client, users_client
from shared.auth import ADMIN, ANALYST, AUDITOR, require_roles
from shared.responses import error_response, register_error_handlers, success_response

SERVICE_NAME = "Threat Intelligence Service"

# The assignment requires every route to include the full name of the student who built it.
# The blueprint adds this prefix to every route below, e.g. /threats -> /sleiman-koumaira/threats
ROUTE_PREFIX = "/sleiman-koumaira"

# Threat alerts (Service 8 notifications) are sent for these severities, to these roles.
ALERT_SEVERITIES = ("High", "Critical")
ALERT_RECIPIENT_ROLES = (ADMIN, ANALYST)

threat_routes = Blueprint("threat_routes", __name__)


def get_repository():
    return ThreatRepository(current_app.config["DATABASE_PATH"])


def send_threat_alerts(threat):
    """
    Notify every active Security Administrator and Security Analyst about a High or Critical
    threat. Recipients come from Service 1; notifications are created in Service 8.
    Returns how many alerts were created. A failure here never cancels the threat itself.
    """
    if threat.severity not in ALERT_SEVERITIES:
        return 0
    try:
        users = users_client.list_users(g.authorization_header)
    except users_client.UsersServiceUnavailable:
        return 0

    recipients = [
        user["id"] for user in users
        if user.get("role") in ALERT_RECIPIENT_ROLES and user.get("account_status") == "Active"
    ]
    sent = 0
    for user_id in recipients:
        created = notification_client.send_notification(
            user_id=user_id,
            title=f"{threat.severity} threat: {threat.threat_type} {threat.threat_value}",
            message=(
                f"A {threat.severity} {threat.threat_type} threat indicator ({threat.threat_value}) "
                f"was added from {threat.source}: {threat.description}"
            ),
            notification_type="Threat Alert",
            severity=threat.severity,
        )
        sent += created
    return sent


def record_change(action, description, severity="Information"):
    """Data modifications must be recorded in the Security Audit Logging Service (Service 5)."""
    audit_client.send_audit_log(
        user_id=g.current_user["user_id"],
        action=action,
        description=description,
        severity=severity,
        related_service=SERVICE_NAME,
    )


@threat_routes.route("/threats", methods=["POST"])
@require_roles(ADMIN)
def add_threat():
    """Add Threat Indicator - Sleiman Koumaira"""
    threat_data, errors = validate_new_threat(request.get_json(silent=True))
    if errors:
        return error_response("Validation failed", 400, errors)

    repository = get_repository()
    existing = repository.find_by_type_and_value(threat_data["threat_type"], threat_data["threat_value"])
    if existing:
        return error_response(
            f"Duplicate threat indicator: this {threat_data['threat_type']} "
            f"is already stored with ID {existing.threat_id}",
            409,
        )

    try:
        threat = repository.create(threat_data)
    except sqlite3.IntegrityError:
        # Second line of defence: the database's UNIQUE(threat_type, threat_value) rule
        # catches a duplicate that slipped in between our check and the insert.
        return error_response("Duplicate threat indicator", 409)

    record_change(
        "CREATE_THREAT",
        f"Added threat {threat.threat_id}: {threat.threat_type} '{threat.threat_value}' ({threat.severity})",
    )
    message = "Threat indicator added successfully"
    if threat.severity in ALERT_SEVERITIES:
        message += f"; threat alert sent to {send_threat_alerts(threat)} user(s)"
    return success_response(threat.to_dict(), message, 201)


@threat_routes.route("/threats", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_all_threats():
    """Retrieve All Threat Indicators - Sleiman Koumaira"""
    threats = get_repository().get_all()
    return success_response([threat.to_dict() for threat in threats])


@threat_routes.route("/threats/search", methods=["GET"])
# The Auditor role description says "Search threat indicators", although the Service 4
# endpoint list omits it. We allow it (read-only) and note the conflict in the report.
@require_roles(ADMIN, ANALYST, AUDITOR)
def search_threats():
    """Search Threat Indicators - Sleiman Koumaira"""
    criteria, errors = validate_search_criteria(request.args)
    if errors:
        return error_response("Invalid search criteria", 400, errors)

    threats = get_repository().search(criteria)
    return success_response([threat.to_dict() for threat in threats])


@threat_routes.route("/threats/<int:threat_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_threat(threat_id):
    """Retrieve Specific Threat Indicator - Sleiman Koumaira"""
    threat = get_repository().get_by_id(threat_id)
    if threat is None:
        return error_response(f"Threat indicator with ID {threat_id} not found", 404)
    return success_response(threat.to_dict())


@threat_routes.route("/threats/<int:threat_id>", methods=["PUT"])
@require_roles(ADMIN)
def update_threat(threat_id):
    """Update Threat Information - Sleiman Koumaira"""
    changes, errors = validate_threat_update(request.get_json(silent=True))
    if errors:
        return error_response("Validation failed", 400, errors)

    repository = get_repository()
    old_threat = repository.get_by_id(threat_id)
    if old_threat is None:
        return error_response(f"Threat indicator with ID {threat_id} not found", 404)

    updated_threat = repository.update(threat_id, changes)
    changed = ", ".join(
        f"{field}: '{getattr(old_threat, field)}' -> '{value}'" for field, value in changes.items()
    )
    record_change("UPDATE_THREAT", f"Updated threat {threat_id}: {changed}")
    return success_response(updated_threat.to_dict(), "Threat information updated successfully")


@threat_routes.route("/threats/<int:threat_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_threat(threat_id):
    """Delete Threat Indicator - Sleiman Koumaira"""
    repository = get_repository()
    threat = repository.get_by_id(threat_id)
    if threat is None:
        return error_response(f"Threat indicator with ID {threat_id} not found", 404)

    repository.delete(threat_id)
    record_change(
        "DELETE_THREAT",
        f"Deleted threat {threat_id}: {threat.threat_type} '{threat.threat_value}'",
        severity="Warning",
    )
    return success_response(message=f"Threat indicator {threat_id} deleted successfully")


def create_app(database_path=None):
    """Build the Flask app. Tests pass their own temporary database_path."""
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = database_path or config.DATABASE_PATHS["threats"]
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False  # keep JSON fields in the order we wrote them
    app.register_blueprint(threat_routes, url_prefix=ROUTE_PREFIX)
    register_error_handlers(app)
    return app


if __name__ == "__main__":
    if not Path(config.DATABASE_PATHS["threats"]).exists():
        raise SystemExit("Database not found. First run:  python -m database.init_db")
    create_app().run(host="127.0.0.1", port=config.SERVICE_PORTS["threats"])
