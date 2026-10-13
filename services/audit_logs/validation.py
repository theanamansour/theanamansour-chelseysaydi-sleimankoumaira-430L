from datetime import date

SEVERITIES = ("Information", "Warning", "Error", "Critical")
CREATE_FIELDS = (
    "user_id",
    "action",
    "description",
    "severity",
    "related_service",
)
SEARCH_FIELDS = ("user_id", "date", "action", "severity", "related_service")


def positive_id(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return f"{field} must be a positive whole number"
    return None


def validate_create(data):
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    errors = []
    unknown = [field for field in data if field not in CREATE_FIELDS]
    if unknown:
        errors.append(f"Unknown field(s): {', '.join(unknown)}")

    clean = {}
    user_id = data.get("user_id")
    if user_id is not None:
        problem = positive_id(user_id, "user_id")
        if problem:
            errors.append(problem)
        else:
            clean["user_id"] = user_id
    else:
        clean["user_id"] = None

    for field, maximum in (
        ("action", 100),
        ("description", 1000),
        ("related_service", 100),
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

    return (None, errors) if errors else (clean, [])


def validate_search(query):
    unknown = [field for field in query if field not in SEARCH_FIELDS]
    if unknown:
        return None, [f"Unknown search parameter(s): {', '.join(unknown)}"]

    criteria = {}
    errors = []
    for field in SEARCH_FIELDS:
        raw = query.get(field)
        if raw is not None and raw.strip():
            criteria[field] = raw.strip()

    if not criteria:
        return None, [
            f"Provide at least one search parameter: {', '.join(SEARCH_FIELDS)}"
        ]

    if "user_id" in criteria:
        try:
            user_id = int(criteria["user_id"])
        except ValueError:
            user_id = 0
        problem = positive_id(user_id, "user_id")
        if problem:
            errors.append(problem)
        else:
            criteria["user_id"] = user_id

    if "severity" in criteria and criteria["severity"] not in SEVERITIES:
        errors.append(f"severity must be one of: {', '.join(SEVERITIES)}")

    if "date" in criteria:
        try:
            date.fromisoformat(criteria["date"])
        except ValueError:
            errors.append("date must use YYYY-MM-DD format")

    for field in ("action", "related_service"):
        if field in criteria and len(criteria[field]) > 100:
            errors.append(f"{field} must be at most 100 characters")

    return (None, errors) if errors else (criteria, [])
