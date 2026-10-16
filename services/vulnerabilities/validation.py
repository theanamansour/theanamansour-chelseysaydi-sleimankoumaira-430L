"""Input validation and lifecycle rules for Service 7.

Every function returns (clean_data, errors). errors is a list of readable
messages; when it is not empty the request is rejected with 400.
"""
import re
from datetime import datetime, timedelta, timezone

SEVERITIES = ("Low", "Medium", "High", "Critical")
STATUSES = ("Open", "Under Investigation", "In Progress", "Resolved", "Closed")
# The only allowed move from each status (Open -> ... -> Closed).
NEXT_STATUS = {
    "Open": "Under Investigation",
    "Under Investigation": "In Progress",
    "In Progress": "Resolved",
    "Resolved": "Closed",
}
FINISHED_STATUSES = ("Resolved", "Closed")

CREATE_FIELDS = (
    "vulnerability_title", "description", "cve_identifier", "cvss_score",
    "severity", "affected_asset_id", "discovery_source",
)
UPDATE_FIELDS = ("description", "severity", "status", "cvss_score", "resolution_date")
SEARCH_FIELDS = ("cve", "severity", "status", "asset_id")
TEXT_LIMITS = {"vulnerability_title": 150, "description": 2000, "discovery_source": 150}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


def severity_for_cvss(score):
    """CVSS v3 rating bands: 0-3.9 Low, 4-6.9 Medium, 7-8.9 High, 9-10 Critical."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _text(data, field, errors, clean):
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{field} is required")
    elif len(value.strip()) > TEXT_LIMITS[field]:
        errors.append(f"{field} must be at most {TEXT_LIMITS[field]} characters")
    else:
        clean[field] = value.strip()


def _cvss(value, errors):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append("cvss_score must be a number between 0.0 and 10.0")
        return None
    if not 0 <= value <= 10:
        errors.append("cvss_score must be between 0.0 and 10.0")
        return None
    if abs(value * 10 - round(value * 10)) > 1e-9:
        errors.append("cvss_score can have at most one decimal place")
        return None
    return round(float(value), 1)


def _severity(value, errors):
    if value not in SEVERITIES:
        errors.append(f"severity must be one of: {', '.join(SEVERITIES)}")
        return None
    return value


def _check_consistency(score, severity, errors):
    if score is not None and severity is not None:
        expected = severity_for_cvss(score)
        if severity != expected:
            errors.append(
                f"severity must be {expected} for a CVSS score of {score} "
                "(Low 0.0-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0)"
            )


def _unknown(data, allowed, errors, label="field"):
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        errors.append(f"Unknown or read-only {label}(s): {', '.join(unknown)}")


def validate_create(data):
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    errors = []
    _unknown(data, CREATE_FIELDS, errors)
    clean = {}
    for field in TEXT_LIMITS:
        _text(data, field, errors, clean)

    cve = data.get("cve_identifier")
    if not isinstance(cve, str) or not CVE_PATTERN.fullmatch(cve.strip()):
        errors.append("cve_identifier must look like CVE-2024-12345")
    else:
        clean["cve_identifier"] = cve.strip().upper()

    score = _cvss(data.get("cvss_score"), errors) if "cvss_score" in data else None
    if "cvss_score" not in data:
        errors.append("cvss_score is required")
    severity = _severity(data.get("severity"), errors)
    _check_consistency(score, severity, errors)
    if score is not None:
        clean["cvss_score"] = score
    if severity is not None:
        clean["severity"] = severity

    asset_id = data.get("affected_asset_id")
    if isinstance(asset_id, bool) or not isinstance(asset_id, int) or asset_id < 1:
        errors.append("affected_asset_id must be a positive whole number")
    else:
        clean["affected_asset_id"] = asset_id

    return (None, errors) if errors else (clean, [])


def parse_timestamp(value):
    for pattern in DATE_FORMATS:
        try:
            return datetime.strptime(value, pattern)
        except (TypeError, ValueError):
            continue
    return None


def validate_update(data, current, now=None):
    """Check an update against the vulnerability's current record."""
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]
    if current["status"] == "Closed":
        return None, ["Closed vulnerabilities cannot be modified"]

    errors = []
    _unknown(data, UPDATE_FIELDS, errors)
    changes = {}

    if "description" in data:
        _text(data, "description", errors, changes)

    score = current["cvss_score"]
    if "cvss_score" in data:
        score = _cvss(data["cvss_score"], errors)
        if score is not None:
            changes["cvss_score"] = score

    severity = current["severity"]
    if "severity" in data:
        severity = _severity(data["severity"], errors)
        if severity is not None:
            changes["severity"] = severity
    if "cvss_score" in data or "severity" in data:
        _check_consistency(score, severity, errors)

    status = current["status"]
    if "status" in data:
        requested = data["status"]
        if requested not in STATUSES:
            errors.append(f"status must be one of: {', '.join(STATUSES)}")
        elif requested == current["status"]:
            errors.append(f"status is already {requested}")
        elif requested != NEXT_STATUS[current["status"]]:
            errors.append(
                f"Invalid status transition from {current['status']} to {requested}; "
                f"the next allowed status is {NEXT_STATUS[current['status']]}"
            )
        else:
            status = requested
            changes["status"] = requested

    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    if "resolution_date" in data:
        moment = parse_timestamp(data["resolution_date"]) if isinstance(data["resolution_date"], str) else None
        created = parse_timestamp(current["created_at"])
        if moment is None:
            errors.append("resolution_date must be YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
        elif status not in FINISHED_STATUSES:
            errors.append("resolution_date can only be set when the status is Resolved or Closed")
        elif created is not None and moment.date() < created.date():
            errors.append("resolution_date cannot be before the vulnerability was created")
        elif moment > now + timedelta(minutes=1):
            errors.append("resolution_date cannot be in the future")
        else:
            changes["resolution_date"] = moment.strftime("%Y-%m-%d %H:%M:%S")
    elif status in FINISHED_STATUSES and current["resolution_date"] is None and not errors:
        # Resolving without a date records the moment it was resolved.
        changes["resolution_date"] = now.strftime("%Y-%m-%d %H:%M:%S")

    return (None, errors) if errors else (changes, [])


def validate_search(args):
    """Validate query parameters for GET /vulnerabilities/search."""
    errors = []
    _unknown(args, SEARCH_FIELDS, errors, label="search parameter")
    filters = {}

    if "cve" in args:
        cve = args["cve"].strip()
        if not 1 <= len(cve) <= 20 or not re.fullmatch(r"[A-Za-z0-9-]+", cve):
            errors.append("cve must be 1-20 letters, digits or dashes (for example CVE-2024 or 6387)")
        else:
            filters["cve"] = cve.upper()
    if "severity" in args:
        if args["severity"] not in SEVERITIES:
            errors.append(f"severity must be one of: {', '.join(SEVERITIES)}")
        else:
            filters["severity"] = args["severity"]
    if "status" in args:
        if args["status"] not in STATUSES:
            errors.append(f"status must be one of: {', '.join(STATUSES)}")
        else:
            filters["status"] = args["status"]
    if "asset_id" in args:
        raw = args["asset_id"]
        if not (raw.isascii() and raw.isdigit()) or int(raw) < 1:
            errors.append("asset_id must be a positive whole number")
        else:
            filters["asset_id"] = int(raw)

    if not filters and not errors:
        errors.append("Provide at least one search parameter: cve, severity, status or asset_id")
    return (None, errors) if errors else (filters, [])
