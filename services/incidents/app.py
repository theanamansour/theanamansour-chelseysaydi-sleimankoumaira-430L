"""
Service 3 - Incident Management Service
Student: Chelsea Saydi

Run from the project root:
    python -m services.incidents.app
"""
import os
import sqlite3

from flask import Flask, current_app, g, jsonify, request

from services.incidents import integrations
from services.incidents.auth import (
    ADMIN,
    ANALYST,
    AUDITOR,
    EMPLOYEE,
    error,
    require_roles,
)
from services.incidents.database import get_database_path, init_db
from services.incidents.repository import IncidentRepository
from services.incidents.validation import (
    validate_assignment,
    validate_create,
    validate_note,
    validate_status,
)

ROUTE_PREFIX = "/chelsea-saydi"
SERVICE_NAME = "Incident Management Service"


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
    return IncidentRepository(current_app.config["DATABASE_PATH"])


def incident_or_404(incident_id):
    incident = repository().get(incident_id)
    if incident is None:
        return None, error(f"Incident with ID {incident_id} not found", 404)
    return incident, None


def can_view(incident):
    user = g.current_user
    if user["role"] in (ADMIN, AUDITOR):
        return True
    if user["role"] == EMPLOYEE:
        return incident["reporter_id"] == user["user_id"]
    return incident["assigned_analyst_id"] == user["user_id"]


def assigned_analyst_can_modify(incident):
    return (
        g.current_user["role"] != ANALYST
        or incident["assigned_analyst_id"] == g.current_user["user_id"]
    )


def service_problem(exception):
    return error(str(exception), 503)


def audit(action, description):
    integrations.send_audit_log(
        g.current_user["user_id"], action, description, "Information"
    )


def create_app(database_path=None):
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(database_path or get_database_path())
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False
    init_db(app.config["DATABASE_PATH"])

    # 1. Create Incident - Chelsea Saydi
    @app.post(ROUTE_PREFIX + "/incidents")
    @require_roles(ADMIN, EMPLOYEE)
    def create_incident():
        data, errors = validate_create(request.get_json(silent=True))
        if errors:
            return error("Validation failed", 400, errors)

        if (
            g.current_user["role"] == EMPLOYEE
            and data["reporter_id"] != g.current_user["user_id"]
        ):
            return error("Employees may only report incidents as themselves", 403)

        if g.current_user["role"] == ADMIN:
            try:
                reporter = integrations.get_user(
                    data["reporter_id"], g.authorization
                )
            except integrations.ServiceUnavailable as exc:
                return service_problem(exc)
            if reporter is None:
                return error("Reporter user not found", 400)
        if not repository().asset_exists(data["asset_id"]):
            return error("Affected asset not found", 400)

        try:
            incident = repository().create(data)
        except sqlite3.IntegrityError:
            return error("Reporter or affected asset not found", 400)
        audit(
            "INCIDENT_CREATED",
            f"Incident {incident['incident_id']} was created",
        )
        return success(incident, "Incident created successfully", 201)

    # 2. Retrieve All Incidents - Chelsea Saydi
    @app.get(ROUTE_PREFIX + "/incidents")
    @require_roles(ADMIN, AUDITOR)
    def get_incidents():
        return success(repository().all())

    # 3. Retrieve Specific Incident - Chelsea Saydi
    @app.get(ROUTE_PREFIX + "/incidents/<int:incident_id>")
    @require_roles(ADMIN, ANALYST, EMPLOYEE, AUDITOR)
    def get_incident(incident_id):
        incident, problem = incident_or_404(incident_id)
        if problem:
            return problem
        if not can_view(incident):
            return error("You may not view this incident", 403)
        return success(incident)

    # 4. Assign Incident to Analyst - Chelsea Saydi
    @app.put(ROUTE_PREFIX + "/incidents/<int:incident_id>/assign")
    @require_roles(ADMIN)
    def assign_incident(incident_id):
        incident, problem = incident_or_404(incident_id)
        if problem:
            return problem

        analyst_id, errors = validate_assignment(request.get_json(silent=True))
        if errors:
            return error("Validation failed", 400, errors)
        try:
            analyst = integrations.get_user(analyst_id, g.authorization)
        except integrations.ServiceUnavailable as exc:
            return service_problem(exc)
        if analyst is None:
            return error("Analyst user not found", 400)
        if analyst.get("role") != ANALYST:
            return error("Assigned user must have the Security Analyst role", 400)

        incident = repository().assign(incident_id, analyst_id)
        integrations.notify_assigned_analyst(incident)
        audit(
            "INCIDENT_ASSIGNED",
            f"Incident {incident_id} assigned to analyst {analyst_id}",
        )
        return success(incident, "Incident assigned successfully")

    # 5. Update Incident Status - Chelsea Saydi
    @app.put(ROUTE_PREFIX + "/incidents/<int:incident_id>/status")
    @require_roles(ADMIN, ANALYST)
    def update_incident_status(incident_id):
        incident, problem = incident_or_404(incident_id)
        if problem:
            return problem
        if not assigned_analyst_can_modify(incident):
            return error("Analysts may only update incidents assigned to them", 403)

        status, errors = validate_status(
            request.get_json(silent=True), incident["status"]
        )
        if errors:
            return error("Validation failed", 400, errors)

        updated = repository().update_status(incident_id, status)
        audit(
            "INCIDENT_STATUS_UPDATED",
            f"Incident {incident_id} moved from {incident['status']} to {status}",
        )
        return success(updated, "Incident status updated successfully")

    # 6. Add Investigation Notes - Chelsea Saydi
    @app.post(ROUTE_PREFIX + "/incidents/<int:incident_id>/notes")
    @require_roles(ADMIN, ANALYST)
    def add_investigation_note(incident_id):
        incident, problem = incident_or_404(incident_id)
        if problem:
            return problem
        if not assigned_analyst_can_modify(incident):
            return error("Analysts may only add notes to incidents assigned to them", 403)

        content, errors = validate_note(request.get_json(silent=True))
        if errors:
            return error("Validation failed", 400, errors)

        note = repository().add_note(
            incident_id, g.current_user["user_id"], content
        )
        audit(
            "INVESTIGATION_NOTE_ADDED",
            f"Investigation note {note['note_id']} added to incident {incident_id}",
        )
        return success(note, "Investigation note added successfully", 201)

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
    port = int(os.environ.get("INCIDENT_SERVICE_PORT", "5003"))
    create_app().run(host="127.0.0.1", port=port, debug=True)
