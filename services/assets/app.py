"""
Service 2 - Asset Management Service
Owner: Sleiman Koumaira

Run from the project root:
    python -m services.assets.app
The service listens on http://127.0.0.1:5002/sleiman-koumaira/assets

Role permissions are listed on each route. They are enforced once Service 1's shared
token verification is integrated (agreed with the Service 1 owner: no temporary
authentication in this service).
"""
from pathlib import Path

from flask import Blueprint, Flask, current_app, request

from services.assets.repository import AssetRepository
from services.assets.validation import validate_asset_update, validate_new_asset, validate_search_criteria
from shared import config
from shared.responses import error_response, register_error_handlers, success_response

SERVICE_NAME = "Asset Management Service"

# The assignment requires every route to include the full name of the student who built it.
# The blueprint adds this prefix to every route below, e.g. /assets -> /sleiman-koumaira/assets
ROUTE_PREFIX = "/sleiman-koumaira"

asset_routes = Blueprint("asset_routes", __name__)


def get_repository():
    return AssetRepository(current_app.config["DATABASE_PATH"])


@asset_routes.route("/assets", methods=["POST"])
def add_asset():
    """
    Add New Asset - Sleiman Koumaira
    Allowed roles: Security Administrator
    """
    asset_data, errors = validate_new_asset(request.get_json(silent=True))
    if errors:
        return error_response("Validation failed", 400, errors)

    asset = get_repository().create(asset_data)
    return success_response(asset.to_dict(), "Asset added successfully", 201)


@asset_routes.route("/assets", methods=["GET"])
def get_all_assets():
    """
    Retrieve All Assets - Sleiman Koumaira
    Allowed roles: Security Administrator, Auditor
    """
    assets = get_repository().get_all()
    return success_response([asset.to_dict() for asset in assets])


@asset_routes.route("/assets/search", methods=["GET"])
def search_assets():
    """
    Search Assets - Sleiman Koumaira
    Allowed roles: Security Administrator, Security Analyst, Auditor
    """
    criteria, errors = validate_search_criteria(request.args)
    if errors:
        return error_response("Invalid search criteria", 400, errors)

    assets = get_repository().search(criteria)
    return success_response([asset.to_dict() for asset in assets])


@asset_routes.route("/assets/<int:asset_id>", methods=["GET"])
def get_asset(asset_id):
    """
    Retrieve Specific Asset - Sleiman Koumaira
    Allowed roles: Security Administrator, Security Analyst, Auditor
    """
    asset = get_repository().get_by_id(asset_id)
    if asset is None:
        return error_response(f"Asset with ID {asset_id} not found", 404)
    return success_response(asset.to_dict())


@asset_routes.route("/assets/<int:asset_id>", methods=["PUT"])
def update_asset(asset_id):
    """
    Update Asset Information - Sleiman Koumaira
    Allowed roles: Security Administrator
    """
    changes, errors = validate_asset_update(request.get_json(silent=True))
    if errors:
        return error_response("Validation failed", 400, errors)

    updated_asset = get_repository().update(asset_id, changes)
    if updated_asset is None:
        return error_response(f"Asset with ID {asset_id} not found", 404)
    return success_response(updated_asset.to_dict(), "Asset information updated successfully")


@asset_routes.route("/assets/<int:asset_id>", methods=["DELETE"])
def delete_asset(asset_id):
    """
    Delete Asset - Sleiman Koumaira
    Allowed roles: Security Administrator
    """
    if not get_repository().delete(asset_id):
        return error_response(f"Asset with ID {asset_id} not found", 404)
    return success_response(message=f"Asset {asset_id} deleted successfully")


def create_app(database_path=None):
    """Build the Flask app. Tests pass their own temporary database_path."""
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = database_path or config.DATABASE_PATH
    app.config["SERVICE_NAME"] = SERVICE_NAME
    app.json.sort_keys = False  # keep JSON fields in the order we wrote them
    app.register_blueprint(asset_routes, url_prefix=ROUTE_PREFIX)
    register_error_handlers(app)
    return app


if __name__ == "__main__":
    if not Path(config.DATABASE_PATH).exists():
        raise SystemExit("Database not found. First run:  python -m database.init_db")
    create_app().run(host="127.0.0.1", port=config.SERVICE_PORTS["assets"])
