"""
Service 2 - Asset Management Service (Sleiman Koumaira)

Input validation. Every function returns (clean_data, errors):
  - errors is a list of messages for the client (empty list = input is valid)
  - clean_data is the trimmed/normalized data that is safe to store
"""
import ipaddress

from services.assets.models import (
    ASSET_STATUSES,
    ASSET_TYPES,
    CRITICALITY_LEVELS,
    DEFAULT_STATUS,
    OPTIONAL_FIELDS,
    REQUIRED_FIELDS,
    SEARCH_FIELDS,
    UPDATABLE_FIELDS,
)

MAX_TEXT_LENGTH = 100
TEXT_FIELDS = ("asset_name", "asset_type", "ip_address", "department", "criticality",
               "operating_system", "location", "status")


def validate_new_asset(data):
    """Check the JSON body of POST /assets."""
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    errors = _unknown_field_errors(data, REQUIRED_FIELDS + OPTIONAL_FIELDS)
    clean = {}

    for field in REQUIRED_FIELDS:
        value, error = _check_field(field, data.get(field), required=True)
        if error:
            errors.append(error)
        else:
            clean[field] = value

    for field in OPTIONAL_FIELDS:
        value, error = _check_field(field, data.get(field), required=False)
        if error:
            errors.append(error)
        else:
            clean[field] = value

    if clean.get("status") is None:
        clean["status"] = DEFAULT_STATUS

    return (None, errors) if errors else (clean, [])


def validate_asset_update(data):
    """Check the JSON body of PUT /assets/{id}. Only the fields in UPDATABLE_FIELDS may change."""
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    not_updatable = [field for field in data if field not in UPDATABLE_FIELDS]
    if not_updatable:
        return None, [
            f"These fields cannot be updated: {', '.join(not_updatable)}. "
            f"Allowed fields: {', '.join(UPDATABLE_FIELDS)}"
        ]

    errors = []
    clean = {}
    for field in UPDATABLE_FIELDS:
        if field in data:
            value, error = _check_field(field, data[field], required=True)
            if error:
                errors.append(error)
            else:
                clean[field] = value

    return (None, errors) if errors else (clean, [])


def validate_search_criteria(query_params):
    """Check the query parameters of GET /assets/search (e.g. ?criticality=High&department=IT)."""
    unknown = [name for name in query_params if name not in SEARCH_FIELDS]
    if unknown:
        return None, [
            f"Unknown search parameter(s): {', '.join(unknown)}. "
            f"Allowed: {', '.join(SEARCH_FIELDS)}"
        ]

    criteria = {}
    for field in SEARCH_FIELDS:
        value = query_params.get(field, "").strip()
        if value:
            criteria[field] = value

    if not criteria:
        return None, [f"Provide at least one search parameter: {', '.join(SEARCH_FIELDS)}"]

    errors = []
    if "asset_type" in criteria and criteria["asset_type"] not in ASSET_TYPES:
        errors.append(f"asset_type must be one of: {', '.join(ASSET_TYPES)}")
    if "criticality" in criteria and criteria["criticality"] not in CRITICALITY_LEVELS:
        errors.append(f"criticality must be one of: {', '.join(CRITICALITY_LEVELS)}")

    return (None, errors) if errors else (criteria, [])


def _check_field(field, value, required):
    """
    Validate one field. Returns (clean_value, error).
    Optional fields that are missing or null give (None, None).
    """
    if value is None:
        return (None, f"{field} is required") if required else (None, None)

    if field == "owner_id":
        # bool is excluded on purpose: in Python, True counts as the integer 1.
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return None, "owner_id must be a positive whole number (the owner's user ID)"
        return value, None

    if not isinstance(value, str):
        return None, f"{field} must be text"
    value = value.strip()
    if not value:
        if required:
            return None, f"{field} is required"
        return None, f"{field} cannot be blank (leave it out if it does not apply)"
    if len(value) > MAX_TEXT_LENGTH:
        return None, f"{field} must be at most {MAX_TEXT_LENGTH} characters"

    if field == "ip_address":
        try:
            return str(ipaddress.ip_address(value)), None  # accepts IPv4 and IPv6
        except ValueError:
            return None, f"'{value}' is not a valid IPv4 or IPv6 address"
    if field == "asset_type" and value not in ASSET_TYPES:
        return None, f"asset_type must be one of: {', '.join(ASSET_TYPES)}"
    if field == "criticality" and value not in CRITICALITY_LEVELS:
        return None, f"criticality must be one of: {', '.join(CRITICALITY_LEVELS)}"
    if field == "status" and value not in ASSET_STATUSES:
        return None, f"status must be one of: {', '.join(ASSET_STATUSES)}"

    return value, None


def _unknown_field_errors(data, allowed_fields):
    unknown = [field for field in data if field not in allowed_fields]
    if unknown:
        return [f"Unknown field(s): {', '.join(unknown)}"]
    return []
