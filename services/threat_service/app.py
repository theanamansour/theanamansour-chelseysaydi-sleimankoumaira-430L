"""
Service 4 - Threat Intelligence Service
Owner: Sleiman Koumaira

Run from the project root:
    python -m services.threat_service.app
The service listens on http://127.0.0.1:5004/sleiman-koumaira/threats
"""
import sqlite3
from pathlib import Path

from flask import Blueprint, Flask, current_app, g, request

from services.threat_service.repository import ThreatRepository
from services.threat_service.validation import (
    validate_new_threat,
    validate_search_criteria,
    validate_threat_update,
)
from shared import audit_client, config
from shared.auth import ADMIN, ANALYST, AUDITOR, require_roles
from shared.responses import error_response, register_error_handlers, success_response

SERVICE_NAME = "Threat Intelligence Service"

# The assignment requires every route to include the full name of the student who built it.
# The blueprint adds this prefix to every route below, e.g. /threats -> /sleiman-koumaira/threats
ROUTE_PREFIX = "/sleiman-koumaira"

threat_routes = Blueprint("threat_routes", __name__)


def get_repository():
    return ThreatRepository(current_app.config["DATABASE_PATH"])


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
    return success_response(threat.to_dict(), "Threat indicator added successfully", 201)


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
    app.config["DATABASE_PATH"] = database_path or config.DATABASE_PATH
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False  # keep JSON fields in the order we wrote them
    app.register_blueprint(threat_routes, url_prefix=ROUTE_PREFIX)
    register_error_handlers(app)
    return app


if __name__ == "__main__":
    if not Path(config.DATABASE_PATH).exists():
        raise SystemExit("Database not found. First run:  python -m database.init_db")
    create_app().run(host="127.0.0.1", port=config.SERVICE_PORTS["threats"])
