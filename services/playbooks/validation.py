SEVERITIES = ("Low", "Medium", "High", "Critical")
ACTION_STATUSES = ("Pending", "In Progress", "Completed")
NEXT_STATUS = {"Pending": "In Progress", "In Progress": "Completed"}
PLAYBOOK_FIELDS = (
    "playbook_name",
    "description",
    "incident_category",
    "severity",
)
ACTION_FIELDS = ("action_description", "step_number")
ACTION_UPDATE_FIELDS = ("status", "assigned_user_id")


def positive_id(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return f"{field} must be a positive whole number"
    return None


def validate_playbook(data):
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    errors = []
    unknown = [field for field in data if field not in PLAYBOOK_FIELDS]
    if unknown:
        errors.append(f"Unknown field(s): {', '.join(unknown)}")

    clean = {}
    for field, maximum in (
        ("playbook_name", 150),
        ("description", 2000),
        ("incident_category", 100),
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


def validate_new_action(data):
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    errors = []
    unknown = [field for field in data if field not in ACTION_FIELDS]
    if unknown:
        errors.append(f"Unknown field(s): {', '.join(unknown)}")

    clean = {}
    description = data.get("action_description")
    if not isinstance(description, str) or not description.strip():
        errors.append("action_description is required")
    elif len(description.strip()) > 1000:
        errors.append("action_description must be at most 1000 characters")
    else:
        clean["action_description"] = description.strip()

    step_number = data.get("step_number")
    problem = positive_id(step_number, "step_number")
    if problem:
        errors.append(problem)
    else:
        clean["step_number"] = step_number

    return (None, errors) if errors else (clean, [])


def validate_action_update(data, current_status):
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    unknown = [field for field in data if field not in ACTION_UPDATE_FIELDS]
    if unknown:
        return None, [f"Unknown field(s): {', '.join(unknown)}"]
    if "status" not in data:
        return None, ["status is required"]

    errors = []
    status = data["status"]
    if status not in ACTION_STATUSES:
        errors.append(
            f"status must be one of: {', '.join(ACTION_STATUSES)}"
        )
    else:
        expected = NEXT_STATUS.get(current_status)
        if status != expected:
            if expected is None:
                errors.append("Completed actions cannot change status")
            else:
                errors.append(
                    f"Invalid status transition: {current_status} "
                    f"can only move to {expected}"
                )

    assigned_user_id = data.get("assigned_user_id")
    if assigned_user_id is not None:
        problem = positive_id(assigned_user_id, "assigned_user_id")
        if problem:
            errors.append(problem)

    clean = {
        "status": status,
        "assigned_user_id": assigned_user_id,
    }
    return (None, errors) if errors else (clean, [])
