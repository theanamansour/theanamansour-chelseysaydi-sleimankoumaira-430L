"""
Service 9 - Security Playbook and Response Automation Service
Student: Chelsea Saydi

Run from the project root:
    python -m services.playbooks.app
"""
import os
import sqlite3

from flask import Flask, current_app, g, jsonify, request

from services.playbooks.auth import (
    ADMIN,
    ANALYST,
    AUDITOR,
    error,
    require_roles,
    send_audit_log,
)
from services.playbooks.database import get_database_path, init_db
from services.playbooks.repository import PlaybookRepository
from services.playbooks.validation import (
    validate_action_update,
    validate_new_action,
    validate_playbook,
)

ROUTE_PREFIX = "/chelsea-saydi"
SERVICE_NAME = "Security Playbook and Response Automation Service"


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
    return PlaybookRepository(current_app.config["DATABASE_PATH"])


def create_app(database_path=None):
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(database_path or get_database_path())
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False
    init_db(app.config["DATABASE_PATH"])

    # 1. Create Response Playbook - Chelsea Saydi
    @app.post(ROUTE_PREFIX + "/playbooks")
    @require_roles(ADMIN)
    def create_playbook():
        data, errors = validate_playbook(request.get_json(silent=True))
        if errors:
            return error("Validation failed", 400, errors)

        try:
            playbook = repository().create(data, g.current_user["user_id"])
        except sqlite3.IntegrityError:
            return error(
                f"A playbook named '{data['playbook_name']}' already exists", 409
            )
        send_audit_log(
            g.current_user["user_id"],
            "PLAYBOOK_CREATED",
            f"Playbook {playbook['playbook_id']} was created",
        )
        return success(playbook, "Playbook created successfully", 201)

    # 2. Retrieve All Playbooks - Chelsea Saydi
    @app.get(ROUTE_PREFIX + "/playbooks")
    @require_roles(ADMIN, ANALYST, AUDITOR)
    def get_playbooks():
        return success(repository().all())

    # 3. Retrieve Specific Playbook - Chelsea Saydi
    @app.get(ROUTE_PREFIX + "/playbooks/<int:playbook_id>")
    @require_roles(ADMIN, ANALYST, AUDITOR)
    def get_playbook(playbook_id):
        playbook = repository().get(playbook_id)
        if playbook is None:
            return error(f"Playbook with ID {playbook_id} not found", 404)
        return success(playbook)

    # 4. Add Response Action - Chelsea Saydi
    @app.post(ROUTE_PREFIX + "/playbooks/<int:playbook_id>/actions")
    @require_roles(ADMIN, ANALYST)
    def add_response_action(playbook_id):
        data, errors = validate_new_action(request.get_json(silent=True))
        if errors:
            return error("Validation failed", 400, errors)

        try:
            action = repository().add_action(
                playbook_id, data, g.current_user["user_id"]
            )
        except sqlite3.IntegrityError:
            return error(
                f"Step number {data['step_number']} already exists "
                f"in playbook {playbook_id}",
                409,
            )
        if action is None:
            return error(f"Playbook with ID {playbook_id} not found", 404)

        send_audit_log(
            g.current_user["user_id"],
            "RESPONSE_ACTION_ADDED",
            f"Action {action['action_id']} added to playbook {playbook_id}",
        )
        return success(action, "Response action added successfully", 201)

    # 5. Update Response Action Status - Chelsea Saydi
    @app.put(ROUTE_PREFIX + "/actions/<int:action_id>/status")
    @require_roles(ADMIN, ANALYST)
    def update_action_status(action_id):
        action = repository().get_action(action_id)
        if action is None:
            return error(f"Response action with ID {action_id} not found", 404)

        data, errors = validate_action_update(
            request.get_json(silent=True), action["status"]
        )
        if errors:
            return error("Validation failed", 400, errors)

        if (
            action["status"] == "Pending"
            and data["status"] == "In Progress"
            and not repository().earlier_actions_complete(action)
        ):
            return error(
                "Earlier response actions must be completed first", 409
            )

        try:
            updated = repository().update_action(
                action_id,
                data["status"],
                data["assigned_user_id"],
                g.current_user["user_id"],
            )
        except sqlite3.IntegrityError:
            return error(
                f"User with ID {data['assigned_user_id']} not found", 400
            )
        send_audit_log(
            g.current_user["user_id"],
            "RESPONSE_ACTION_UPDATED",
            f"Action {action_id} moved from "
            f"{action['status']} to {data['status']}",
        )
        return success(updated, "Response action updated successfully")

    # 6. Delete Playbook - Chelsea Saydi
    @app.delete(ROUTE_PREFIX + "/playbooks/<int:playbook_id>")
    @require_roles(ADMIN)
    def delete_playbook(playbook_id):
        if not repository().delete(playbook_id):
            return error(f"Playbook with ID {playbook_id} not found", 404)
        send_audit_log(
            g.current_user["user_id"],
            "PLAYBOOK_DELETED",
            f"Playbook {playbook_id} was deleted",
            "Warning",
        )
        return success(message=f"Playbook {playbook_id} deleted successfully")

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
    port = int(os.environ.get("PLAYBOOK_SERVICE_PORT", "5009"))
    create_app().run(host="127.0.0.1", port=port, debug=True)
