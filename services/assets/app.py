"""
Service 2 - Asset Management Service
Owner: Sleiman Koumaira

Run from the project root:
    python -m services.assets.app
The service listens on http://127.0.0.1:5002/sleiman-koumaira/assets
"""
from pathlib import Path

from flask import Blueprint, Flask, current_app, g, request

from services.assets.repository import AssetRepository
from services.assets.validation import validate_asset_update, validate_new_asset, validate_search_criteria
from shared import audit_client, config, users_client
from shared.auth import ADMIN, ANALYST, AUDITOR, require_roles
from shared.responses import error_response, register_error_handlers, success_response

SERVICE_NAME = "Asset Management Service"

# The assignment requires every route to include the full name of the student who built it.
# The blueprint adds this prefix to every route below, e.g. /assets -> /sleiman-koumaira/assets
ROUTE_PREFIX = "/sleiman-koumaira"

asset_routes = Blueprint("asset_routes", __name__)


def get_repository():
    return AssetRepository(current_app.config["DATABASE_PATH"])


def record_change(action, description, severity="Information"):
    """Data modifications must be recorded in the Security Audit Logging Service (Service 5)."""
    audit_client.send_audit_log(
        user_id=g.current_user["user_id"],
        action=action,
        description=description,
        severity=severity,
        related_service=SERVICE_NAME,
    )


def check_owner_exists(owner_id):
    """
    The owner must be a real user of Service 1. Returns an error response, or None if the owner exists.
    (Each service has its own database, so this replaces a SQLite foreign key.)
    """
    try:
        exists = users_client.user_exists(owner_id, g.authorization_header)
    except users_client.UsersServiceUnavailable:
        return error_response("Users service (Service 1) is unavailable, cannot check owner_id", 503)
    if not exists:
        return error_response("Validation failed", 400, [f"owner_id {owner_id} does not match any registered user"])
    return None


@asset_routes.route("/assets", methods=["POST"])
@require_roles(ADMIN)
def add_asset():
    """Add New Asset - Sleiman Koumaira"""
    asset_data, errors = validate_new_asset(request.get_json(silent=True))
    if errors:
        return error_response("Validation failed", 400, errors)

    owner_problem = check_owner_exists(asset_data["owner_id"])
    if owner_problem:
        return owner_problem

    asset = get_repository().create(asset_data)
    record_change(
        "CREATE_ASSET",
        f"Added asset {asset.asset_id}: {asset.asset_type} '{asset.asset_name}' ({asset.criticality})",
    )
    return success_response(asset.to_dict(), "Asset added successfully", 201)


@asset_routes.route("/assets", methods=["GET"])
@require_roles(ADMIN, AUDITOR)
def get_all_assets():
    """Retrieve All Assets - Sleiman Koumaira"""
    assets = get_repository().get_all()
    return success_response([asset.to_dict() for asset in assets])


@asset_routes.route("/assets/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def search_assets():
    """Search Assets - Sleiman Koumaira"""
    criteria, errors = validate_search_criteria(request.args)
    if errors:
        return error_response("Invalid search criteria", 400, errors)

    assets = get_repository().search(criteria)
    return success_response([asset.to_dict() for asset in assets])


@asset_routes.route("/assets/<int:asset_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR)
def get_asset(asset_id):
    """Retrieve Specific Asset - Sleiman Koumaira"""
    asset = get_repository().get_by_id(asset_id)
    if asset is None:
        return error_response(f"Asset with ID {asset_id} not found", 404)
    return success_response(asset.to_dict())


@asset_routes.route("/assets/<int:asset_id>", methods=["PUT"])
@require_roles(ADMIN)
def update_asset(asset_id):
    """Update Asset Information - Sleiman Koumaira"""
    changes, errors = validate_asset_update(request.get_json(silent=True))
    if errors:
        return error_response("Validation failed", 400, errors)

    repository = get_repository()
    old_asset = repository.get_by_id(asset_id)
    if old_asset is None:
        return error_response(f"Asset with ID {asset_id} not found", 404)

    if "owner_id" in changes:
        owner_problem = check_owner_exists(changes["owner_id"])
        if owner_problem:
            return owner_problem

    updated_asset = repository.update(asset_id, changes)
    changed = ", ".join(
        f"{field}: '{getattr(old_asset, field)}' -> '{value}'" for field, value in changes.items()
    )
    record_change("UPDATE_ASSET", f"Updated asset {asset_id}: {changed}")
    return success_response(updated_asset.to_dict(), "Asset information updated successfully")


@asset_routes.route("/assets/<int:asset_id>", methods=["DELETE"])
@require_roles(ADMIN)
def delete_asset(asset_id):
    """Delete Asset - Sleiman Koumaira"""
    repository = get_repository()
    asset = repository.get_by_id(asset_id)
    if asset is None:
        return error_response(f"Asset with ID {asset_id} not found", 404)

    repository.delete(asset_id)
    record_change(
        "DELETE_ASSET",
        f"Deleted asset {asset_id}: {asset.asset_type} '{asset.asset_name}'",
        severity="Warning",
    )
    return success_response(message=f"Asset {asset_id} deleted successfully")


def create_app(database_path=None):
    """Build the Flask app. Tests pass their own temporary database_path."""
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = database_path or config.DATABASE_PATHS["assets"]
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False  # keep JSON fields in the order we wrote them
    app.register_blueprint(asset_routes, url_prefix=ROUTE_PREFIX)
    register_error_handlers(app)
    return app


if __name__ == "__main__":
    if not Path(config.DATABASE_PATHS["assets"]).exists():
        raise SystemExit("Database not found. First run:  python -m database.init_db")
    create_app().run(host="127.0.0.1", port=config.SERVICE_PORTS["assets"])
