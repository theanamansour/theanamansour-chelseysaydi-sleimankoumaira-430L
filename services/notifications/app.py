"""
Service 8 - Notification and Alert Management Service
Owner: Sleiman Koumaira

Run from the project root:
    python -m services.notifications.app
The service listens on http://127.0.0.1:5008/sleiman-koumaira/notifications

Who sees what:
  - Security Administrator and Auditor: every user's notifications (the Auditor only reads).
  - Security Analyst and Regular Employee: only their own notifications.
  - Other services (e.g. threat alerts from Service 4) create notifications with the
    internal X-Service-Key header instead of a user token.
"""
import sqlite3

from flask import Blueprint, Flask, current_app, g, request

from database.config import get_database_path
from services.notifications.repository import NotificationRepository
from services.notifications.validation import validate_new_notification, validate_search_criteria
from shared import audit_client, config, users_client
from shared.auth import ADMIN, ANALYST, AUDITOR, INTERNAL_SERVICE, REGULAR_EMPLOYEE, require_roles
from shared.responses import error_response, register_error_handlers, success_response

SERVICE_NAME = "Notification and Alert Management Service"

# The assignment requires every route to include the full name of the student who built it.
ROUTE_PREFIX = "/sleiman-koumaira"

# Roles that may only see and mark their own notifications.
OWN_NOTIFICATIONS_ONLY = (ANALYST, REGULAR_EMPLOYEE)

notification_routes = Blueprint("notification_routes", __name__)


def get_repository():
    return NotificationRepository(current_app.config["DATABASE_PATH"])


def log_event(action, description, severity="Information"):
    """Send an event to the Security Audit Logging Service (Service 5)."""
    audit_client.send_audit_log(
        user_id=g.current_user["user_id"],
        action=action,
        description=description,
        severity=severity,
        related_service=SERVICE_NAME,
    )


def deny_if_not_own(owner_id):
    """
    Analysts and Regular Employees may only use their own notifications.
    Returns a 403 response (and records the violation), or None if access is allowed.
    """
    user = g.current_user
    if user["role"] in OWN_NOTIFICATIONS_ONLY and owner_id != user["user_id"]:
        log_event(
            "PERMISSION_DENIED",
            f"{user['role']} '{user['username']}' attempted {request.method} {request.path} "
            f"(notifications of user {owner_id})",
            severity="Warning",
        )
        return error_response("You may only access your own notifications", 403)
    return None


def unknown_recipient(user_id):
    return error_response("Validation failed", 400, [f"user_id {user_id} does not match any registered user"])


@notification_routes.route("/notifications", methods=["POST"])
@require_roles(ADMIN, allow_service_key=True)
def create_notification():
    """Create Notification - Sleiman Koumaira"""
    data, errors = validate_new_notification(request.get_json(silent=True))
    if errors:
        return error_response("Validation failed", 400, errors)

    # A Security Administrator types the user ID, so it is checked with Service 1.
    # Other services (internal key) send IDs they already received from Service 1; for them the
    # shared database's foreign key on user_id is the check.
    if g.current_user["role"] != INTERNAL_SERVICE:
        try:
            exists = users_client.user_exists(data["user_id"], g.authorization_header)
        except users_client.UsersServiceUnavailable:
            return error_response("Users service (Service 1) is unavailable, cannot check user_id", 503)
        if not exists:
            return unknown_recipient(data["user_id"])

    try:
        notification = get_repository().create(data)
    except sqlite3.IntegrityError:  # the user_id foreign key failed in the database
        return unknown_recipient(data["user_id"])
    created_by = "an internal service" if g.current_user["role"] == INTERNAL_SERVICE else g.current_user["username"]
    log_event(
        "CREATE_NOTIFICATION",
        f"Notification {notification.notification_id} ({notification.notification_type}, {notification.severity}) "
        f"created for user {notification.user_id} by {created_by}",
    )
    return success_response(notification.to_dict(), "Notification created successfully", 201)


@notification_routes.route("/notifications/user/<int:user_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, REGULAR_EMPLOYEE, AUDITOR)
def get_user_notifications(user_id):
    """Retrieve User Notifications - Sleiman Koumaira"""
    denied = deny_if_not_own(user_id)
    if denied:
        return denied

    notifications = get_repository().get_for_user(user_id)
    return success_response([n.to_dict() for n in notifications])


@notification_routes.route("/notifications/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def search_notifications():
    """Search Notifications - Sleiman Koumaira"""
    criteria, errors = validate_search_criteria(request.args)
    if errors:
        return error_response("Invalid search criteria", 400, errors)

    if g.current_user["role"] in OWN_NOTIFICATIONS_ONLY:
        if "user_id" in criteria:
            denied = deny_if_not_own(criteria["user_id"])
            if denied:
                return denied
        criteria["user_id"] = g.current_user["user_id"]  # analysts only search their own

    notifications = get_repository().search(criteria)
    return success_response([n.to_dict() for n in notifications])


@notification_routes.route("/notifications/<int:notification_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, REGULAR_EMPLOYEE, AUDITOR)
def get_notification(notification_id):
    """Retrieve Specific Notification - Sleiman Koumaira"""
    notification = get_repository().get_by_id(notification_id)
    if notification is None:
        return error_response(f"Notification with ID {notification_id} not found", 404)

    denied = deny_if_not_own(notification.user_id)
    if denied:
        return denied
    return success_response(notification.to_dict())


@notification_routes.route("/notifications/<int:notification_id>/read", methods=["PUT"])
@require_roles(ADMIN, ANALYST, REGULAR_EMPLOYEE)
def mark_notification_read(notification_id):
    """Mark Notification as Read - Sleiman Koumaira"""
    repository = get_repository()
    notification = repository.get_by_id(notification_id)
    if notification is None:
        return error_response(f"Notification with ID {notification_id} not found", 404)

    denied = deny_if_not_own(notification.user_id)
    if denied:
        return denied

    if notification.status == "Read":
        return success_response(notification.to_dict(), "Notification was already marked as read")

    notification = repository.mark_as_read(notification_id)
    log_event("MARK_NOTIFICATION_READ", f"Notification {notification_id} marked as read at {notification.read_at}")
    return success_response(notification.to_dict(), "Notification marked as read")


@notification_routes.route("/notifications/<int:notification_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_notification(notification_id):
    """Delete Notification - Sleiman Koumaira"""
    repository = get_repository()
    notification = repository.get_by_id(notification_id)
    if notification is None:
        return error_response(f"Notification with ID {notification_id} not found", 404)

    repository.delete(notification_id)
    log_event(
        "DELETE_NOTIFICATION",
        f"Deleted notification {notification_id} of user {notification.user_id}: '{notification.title}'",
        severity="Warning",
    )
    return success_response(message=f"Notification {notification_id} deleted successfully")


def create_app(database_path=None):
    """Build the Flask app. Tests pass their own temporary database_path."""
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(database_path or get_database_path())
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False  # keep JSON fields in the order we wrote them
    app.register_blueprint(notification_routes, url_prefix=ROUTE_PREFIX)
    register_error_handlers(app)
    return app


if __name__ == "__main__":
    if not get_database_path().exists():
        raise SystemExit("Shared database not found. First run:  python -m database.init_db")
    create_app().run(host="127.0.0.1", port=config.SERVICE_PORTS["notifications"])
