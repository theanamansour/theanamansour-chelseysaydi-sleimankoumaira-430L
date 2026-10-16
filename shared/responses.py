"""Helpers that give every service the same JSON response format."""
from flask import jsonify


def success_response(data=None, message=None, status_code=200):
    """Build {"status": "success", "message": ..., "count": ..., "data": ...}."""
    body = {"status": "success"}
    if message:
        body["message"] = message
    if isinstance(data, list):
        body["count"] = len(data)
    if data is not None:
        body["data"] = data
    return jsonify(body), status_code


def error_response(message, status_code, errors=None):
    """Build {"status": "error", "message": ..., "errors": [...]} (the format the assignment asks for)."""
    body = {"status": "error", "message": message}
    if errors:
        body["errors"] = errors
    return jsonify(body), status_code


def register_error_handlers(app):
    """Make Flask's own errors (unknown URL, wrong method, crash) use our JSON format instead of HTML."""

    @app.errorhandler(404)
    def not_found(error):
        return error_response("The requested URL was not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(error):
        return error_response("This HTTP method is not allowed for this URL", 405)

    @app.errorhandler(500)
    def internal_error(error):
        return error_response("Internal server error", 500)
