"""
Service 8 - Notification and Alert Management Service (Sleiman Koumaira)

Input validation. Every function returns (clean_data, errors):
  - errors is a list of messages for the client (empty list = input is valid)
  - clean_data is the trimmed data that is safe to store or search with
"""
from services.notifications.models import (
    NOTIFICATION_TYPES,
    REQUIRED_FIELDS,
    SEARCH_FIELDS,
    SEVERITY_LEVELS,
    STATUSES,
)

MAX_LENGTHS = {"title": 150, "message": 1000}
# Largest number SQLite can store in an INTEGER column.
MAX_USER_ID = 2**63 - 1


def validate_new_notification(data):
    """Check the JSON body of POST /notifications."""
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    unknown = [field for field in data if field not in REQUIRED_FIELDS]
    errors = [f"Unknown field(s): {', '.join(unknown)}"] if unknown else []
    clean = {}

    user_id = data.get("user_id")
    if user_id is None:
        errors.append("user_id is required")
    elif isinstance(user_id, bool) or not isinstance(user_id, int) or not 1 <= user_id <= MAX_USER_ID:
        # bool is excluded on purpose: in Python, True counts as the integer 1.
        errors.append("user_id must be a positive whole number (the receiving user's ID)")
    else:
        clean["user_id"] = user_id

    for field in ("title", "message", "notification_type", "severity"):
        value = data.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"{field} is required")
        elif not isinstance(value, str):
            errors.append(f"{field} must be text")
        elif field in MAX_LENGTHS and len(value.strip()) > MAX_LENGTHS[field]:
            errors.append(f"{field} must be at most {MAX_LENGTHS[field]} characters")
        else:
            clean[field] = value.strip()

    if "notification_type" in clean and clean["notification_type"] not in NOTIFICATION_TYPES:
        errors.append(f"notification_type must be one of: {', '.join(NOTIFICATION_TYPES)}")
    if "severity" in clean and clean["severity"] not in SEVERITY_LEVELS:
        errors.append(f"severity must be one of: {', '.join(SEVERITY_LEVELS)}")

    return (None, errors) if errors else (clean, [])


def validate_search_criteria(query_params):
    """Check the query parameters of GET /notifications/search (e.g. ?status=Unread&severity=High)."""
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
    if "user_id" in criteria:
        text = criteria["user_id"]
        if text.isascii() and text.isdigit() and 1 <= int(text) <= MAX_USER_ID:
            criteria["user_id"] = int(text)
        else:
            errors.append("user_id must be a positive whole number")
    if "notification_type" in criteria and criteria["notification_type"] not in NOTIFICATION_TYPES:
        errors.append(f"notification_type must be one of: {', '.join(NOTIFICATION_TYPES)}")
    if "severity" in criteria and criteria["severity"] not in SEVERITY_LEVELS:
        errors.append(f"severity must be one of: {', '.join(SEVERITY_LEVELS)}")
    if "status" in criteria and criteria["status"] not in STATUSES:
        errors.append(f"status must be one of: {', '.join(STATUSES)}")

    return (None, errors) if errors else (criteria, [])
