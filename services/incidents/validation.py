SEVERITIES = ("Low", "Medium", "High", "Critical")
STATUSES = ("Open", "Under Investigation", "Mitigated", "Resolved", "Closed")
NEXT_STATUS = dict(zip(STATUSES, STATUSES[1:]))
CREATE_FIELDS = (
    "title",
    "description",
    "category",
    "severity",
    "reporter_id",
    "asset_id",
)


def _positive_id(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return f"{name} must be a positive whole number"
    return None


def validate_create(data):
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    errors = []
    unknown = [field for field in data if field not in CREATE_FIELDS]
    if unknown:
        errors.append(f"Unknown field(s): {', '.join(unknown)}")

    clean = {}
    for field, maximum in (
        ("title", 150),
        ("description", 2000),
        ("category", 100),
    ):
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} is required")
        elif len(value.strip()) > maximum:
            errors.append(f"{field} must be at most {maximum} characters")
        else:
            clean[field] = value.strip()

    severity = data.get("severity")
    if severity not in SEVERITIES:
        errors.append(f"severity must be one of: {', '.join(SEVERITIES)}")
    else:
        clean["severity"] = severity

    for field in ("reporter_id", "asset_id"):
        problem = _positive_id(data.get(field), field)
        if problem:
            errors.append(problem)
        else:
            clean[field] = data[field]

    return (None, errors) if errors else (clean, [])


def validate_assignment(data):
    if not isinstance(data, dict) or set(data) != {"analyst_id"}:
        return None, ["Request body must contain only analyst_id"]
    problem = _positive_id(data["analyst_id"], "analyst_id")
    return (None, [problem]) if problem else (data["analyst_id"], [])


def validate_status(data, current_status):
    if not isinstance(data, dict) or set(data) != {"status"}:
        return None, ["Request body must contain only status"]
    status = data["status"]
    if status not in STATUSES:
        return None, [f"status must be one of: {', '.join(STATUSES)}"]
    expected = NEXT_STATUS.get(current_status)
    if status != expected:
        if expected is None:
            return None, ["Closed incidents cannot change status"]
        return None, [
            f"Invalid status transition: {current_status} can only move to {expected}"
        ]
    return status, []


def validate_note(data):
    if not isinstance(data, dict) or set(data) != {"note_content"}:
        return None, ["Request body must contain only note_content"]
    content = data["note_content"]
    if not isinstance(content, str) or not content.strip():
        return None, ["note_content is required"]
    content = content.strip()
    if len(content) > 2000:
        return None, ["note_content must be at most 2000 characters"]
    return content, []
