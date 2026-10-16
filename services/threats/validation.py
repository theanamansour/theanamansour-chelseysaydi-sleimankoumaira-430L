"""
Service 4 - Threat Intelligence Service (Sleiman Koumaira)

Input validation. Every function returns (clean_data, errors):
  - errors is a list of messages for the client (empty list = input is valid)
  - clean_data is the trimmed/normalized data that is safe to store
"""
import ipaddress
import re

from services.threats.models import (
    REQUIRED_FIELDS,
    SEARCH_FIELDS,
    SEVERITY_LEVELS,
    THREAT_TYPES,
    UPDATABLE_FIELDS,
)

MAX_LENGTHS = {"threat_value": 255, "description": 1000, "source": 100}

# A domain is labels separated by dots, ending in a letters-only extension, e.g. "phishing-login.com".
# Each label: letters, digits or hyphens, 1-63 characters, not starting or ending with a hyphen.
DOMAIN_PATTERN = re.compile(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")

# A file hash is hexadecimal (0-9, a-f). Its length tells the algorithm.
HEX_PATTERN = re.compile(r"[a-f0-9]+")
HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def validate_new_threat(data):
    """Check the JSON body of POST /threats."""
    if not isinstance(data, dict) or not data:
        return None, ["Request body must be a non-empty JSON object"]

    errors = _unknown_field_errors(data, REQUIRED_FIELDS)
    clean = {}
    for field in REQUIRED_FIELDS:
        text, error = _clean_text_field(data, field)
        if error:
            errors.append(error)
        else:
            clean[field] = text

    if "threat_type" in clean:
        if clean["threat_type"] not in THREAT_TYPES:
            errors.append(f"threat_type must be one of: {', '.join(THREAT_TYPES)}")
        elif "threat_value" in clean:
            value, error = normalize_threat_value(clean["threat_type"], clean["threat_value"])
            if error:
                errors.append(error)
            else:
                clean["threat_value"] = value

    if "severity" in clean and clean["severity"] not in SEVERITY_LEVELS:
        errors.append(f"severity must be one of: {', '.join(SEVERITY_LEVELS)}")

    return (None, errors) if errors else (clean, [])


def validate_threat_update(data):
    """Check the JSON body of PUT /threats/{id}. Only description, severity and source may change."""
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
            text, error = _clean_text_field(data, field)
            if error:
                errors.append(error)
            else:
                clean[field] = text

    if "severity" in clean and clean["severity"] not in SEVERITY_LEVELS:
        errors.append(f"severity must be one of: {', '.join(SEVERITY_LEVELS)}")

    return (None, errors) if errors else (clean, [])


def validate_search_criteria(query_params):
    """Check the query parameters of GET /threats/search (e.g. ?severity=High&source=AbuseIPDB)."""
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
    if "threat_type" in criteria and criteria["threat_type"] not in THREAT_TYPES:
        errors.append(f"threat_type must be one of: {', '.join(THREAT_TYPES)}")
    if "severity" in criteria and criteria["severity"] not in SEVERITY_LEVELS:
        errors.append(f"severity must be one of: {', '.join(SEVERITY_LEVELS)}")

    return (None, errors) if errors else (criteria, [])


def normalize_threat_value(threat_type, value):
    """
    Check that the value has the right format for its type and return it in one standard form,
    so that "EVIL.com" and "evil.com" are recognised as the same indicator.
    """
    if threat_type == "IP Address":
        try:
            return str(ipaddress.ip_address(value)), None  # accepts IPv4 and IPv6
        except ValueError:
            return None, f"'{value}' is not a valid IPv4 or IPv6 address"

    if threat_type == "Domain":
        domain = value.lower()
        if len(domain) > 253 or not DOMAIN_PATTERN.fullmatch(domain):
            return None, f"'{value}' is not a valid domain name (example: phishing-login.com)"
        return domain, None

    if threat_type == "File Hash":
        file_hash = value.lower()
        if not HEX_PATTERN.fullmatch(file_hash) or len(file_hash) not in HASH_LENGTHS:
            return None, (
                "File hash must be hexadecimal: MD5 (32 characters), "
                "SHA-1 (40 characters) or SHA-256 (64 characters)"
            )
        return file_hash, None

    # Malware Signature and Other are free text (already trimmed and length-checked).
    return value, None


def _clean_text_field(data, field):
    """Return (trimmed_text, error) for one text field."""
    value = data.get(field)
    if value is None or (isinstance(value, str) and not value.strip()):
        return None, f"{field} is required"
    if not isinstance(value, str):
        return None, f"{field} must be text"

    value = value.strip()
    max_length = MAX_LENGTHS.get(field)
    if max_length and len(value) > max_length:
        return None, f"{field} must be at most {max_length} characters"
    return value, None


def _unknown_field_errors(data, allowed_fields):
    unknown = [field for field in data if field not in allowed_fields]
    if unknown:
        return [f"Unknown field(s): {', '.join(unknown)}"]
    return []
