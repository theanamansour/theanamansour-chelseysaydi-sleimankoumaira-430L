"""Automated tests for Service 4 - Threat Intelligence Service (Sleiman Koumaira)."""
import sqlite3

import pytest

from database.init_db import init_database
from services.threat_service.app import ROUTE_PREFIX, create_app
from shared import auth, users_client

# Test data uses reserved documentation values (203.0.113.x IPs, .example domains)
# so we never label a real website or address as malicious.
IP_THREAT = {
    "threat_type": "IP Address",
    "threat_value": "203.0.113.45",
    "description": "Command-and-control server of a botnet",
    "severity": "High",
    "source": "AbuseIPDB",
}
DOMAIN_THREAT = {
    "threat_type": "Domain",
    "threat_value": "secure-bank-login.example",
    "description": "Phishing site copying a bank login page",
    "severity": "Critical",
    "source": "PhishTank",
}
HASH_THREAT = {
    "threat_type": "File Hash",
    "threat_value": "44d88612fea8a8f36de82e1278abb02f",  # MD5 of the harmless EICAR test file
    "description": "EICAR antivirus test file",
    "severity": "Low",
    "source": "VirusTotal",
}
SIGNATURE_THREAT = {
    "threat_type": "Malware Signature",
    "threat_value": "Trojan.GenericKD.4614",
    "description": "Generic trojan detection signature",
    "severity": "Medium",
    "source": "Internal SOC",
}
OTHER_THREAT = {
    "threat_type": "Other Indicators",
    "threat_value": "powershell -EncodedCommand",
    "description": "Obfuscated PowerShell command often used by attackers",
    "severity": "Medium",
    "source": "Internal SOC",
}
ALL_THREATS = [IP_THREAT, DOMAIN_THREAT, HASH_THREAT, SIGNATURE_THREAT, OTHER_THREAT]


@pytest.fixture
def database_path(tmp_path):
    """A brand-new threats database for every test, so tests never touch the real data."""
    return init_database("threats", str(tmp_path / "threats.db"))


@pytest.fixture
def client(database_path):
    return create_app(database_path).test_client()


@pytest.fixture
def stored_threats(client, headers):
    """Insert the five sample threats and return their IDs."""
    ids = []
    for threat in ALL_THREATS:
        response = client.post(f"{ROUTE_PREFIX}/threats", json=threat, headers=headers["admin"])
        assert response.status_code == 201
        ids.append(response.get_json()["data"]["threat_id"])
    return ids


# ---------- POST /threats ----------

@pytest.mark.parametrize("threat", ALL_THREATS, ids=lambda t: t["threat_type"])
def test_admin_can_add_every_threat_type(client, headers, audit_events, threat):
    response = client.post(f"{ROUTE_PREFIX}/threats", json=threat, headers=headers["admin"])

    assert response.status_code == 201
    body = response.get_json()
    assert body["status"] == "success"
    for field, value in threat.items():
        assert body["data"][field] == value
    assert isinstance(body["data"]["threat_id"], int)
    assert body["data"]["date_added"]
    assert audit_events[-1]["action"] == "CREATE_THREAT"


def test_added_threat_is_stored_in_database(client, headers, database_path):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])

    with sqlite3.connect(database_path) as connection:
        row = connection.execute("SELECT threat_type, threat_value, severity FROM threats").fetchone()
    assert row == ("IP Address", "203.0.113.45", "High")


def test_duplicate_threat_is_rejected(client, headers):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])
    response = client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])

    assert response.status_code == 409
    assert "Duplicate" in response.get_json()["message"]


@pytest.mark.parametrize(
    "threat_type, first_value, same_value_written_differently",
    [
        ("Domain", "evil-site.example", "EVIL-Site.Example"),
        ("IP Address", "2001:db8::1", "2001:DB8:0:0:0:0:0:1"),
        ("File Hash", "44d88612fea8a8f36de82e1278abb02f", "44D88612FEA8A8F36DE82E1278ABB02F"),
    ],
)
def test_duplicate_is_detected_even_when_written_differently(
    client, headers, threat_type, first_value, same_value_written_differently
):
    base = {"description": "test", "severity": "High", "source": "test", "threat_type": threat_type}
    first = client.post(f"{ROUTE_PREFIX}/threats", json={**base, "threat_value": first_value}, headers=headers["admin"])
    second = client.post(
        f"{ROUTE_PREFIX}/threats", json={**base, "threat_value": same_value_written_differently}, headers=headers["admin"]
    )

    assert first.status_code == 201
    assert second.status_code == 409


def test_same_value_with_a_different_type_is_allowed(client, headers):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])
    response = client.post(
        f"{ROUTE_PREFIX}/threats", json={**OTHER_THREAT, "threat_value": "203.0.113.45"}, headers=headers["admin"]
    )
    assert response.status_code == 201


@pytest.mark.parametrize(
    "changes, expected_error",
    [
        ({"threat_value": "999.1.1.1"}, "not a valid IPv4 or IPv6 address"),
        ({"threat_value": "192.x.x.x"}, "not a valid IPv4 or IPv6 address"),
        ({"threat_type": "Domain", "threat_value": "not a domain"}, "not a valid domain name"),
        ({"threat_type": "Domain", "threat_value": "-bad-.com"}, "not a valid domain name"),
        ({"threat_type": "File Hash", "threat_value": "xyz123"}, "File hash must be hexadecimal"),
        ({"threat_type": "File Hash", "threat_value": "a" * 31}, "File hash must be hexadecimal"),
        ({"threat_type": "URL"}, "threat_type must be one of"),
        ({"severity": "Extreme"}, "severity must be one of"),
        ({"severity": "high"}, "severity must be one of"),
        ({"description": "   "}, "description is required"),
        ({"source": 123}, "source must be text"),
        ({"description": "x" * 1001}, "description must be at most 1000 characters"),
        ({"is_admin": True}, "Unknown field(s): is_admin"),
    ],
)
def test_invalid_input_is_rejected(client, headers, changes, expected_error):
    response = client.post(f"{ROUTE_PREFIX}/threats", json={**IP_THREAT, **changes}, headers=headers["admin"])

    assert response.status_code == 400
    body = response.get_json()
    assert body["status"] == "error"
    assert any(expected_error in error for error in body["errors"])


def test_missing_required_fields_are_all_reported(client, headers):
    response = client.post(f"{ROUTE_PREFIX}/threats", json={"threat_type": "IP Address"}, headers=headers["admin"])

    assert response.status_code == 400
    errors = response.get_json()["errors"]
    for field in ("threat_value", "description", "severity", "source"):
        assert f"{field} is required" in errors


@pytest.mark.parametrize(
    "request_options",
    [{"data": ""}, {"data": "not json", "content_type": "text/plain"}, {"json": []}, {"json": {}}],
    ids=["empty body", "plain text", "JSON list", "empty object"],
)
def test_empty_or_non_json_body_is_rejected(client, headers, request_options):
    response = client.post(f"{ROUTE_PREFIX}/threats", headers=headers["admin"], **request_options)

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["Request body must be a non-empty JSON object"]


# ---------- Authentication (401) and authorization (403) ----------

ENDPOINTS = [
    ("POST", f"{ROUTE_PREFIX}/threats"),
    ("GET", f"{ROUTE_PREFIX}/threats"),
    ("GET", f"{ROUTE_PREFIX}/threats/1"),
    ("GET", f"{ROUTE_PREFIX}/threats/search?severity=High"),
    ("PUT", f"{ROUTE_PREFIX}/threats/1"),
    ("DELETE", f"{ROUTE_PREFIX}/threats/1"),
]


@pytest.mark.parametrize("method, url", ENDPOINTS)
def test_request_without_token_gets_401(client, audit_events, method, url):
    response = client.open(url, method=method, json={})

    assert response.status_code == 401
    assert response.get_json()["status"] == "error"
    assert audit_events[-1]["action"] == "UNAUTHENTICATED_ACCESS"


def test_invalid_token_gets_401(client, audit_events):
    response = client.get(f"{ROUTE_PREFIX}/threats", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401
    assert response.get_json()["message"] == "Invalid token"  # message comes from Service 1
    assert audit_events[-1]["action"] == "UNAUTHENTICATED_ACCESS"


def test_expired_token_gets_401(client):
    response = client.get(f"{ROUTE_PREFIX}/threats", headers={"Authorization": "Bearer expired-token"})
    assert response.status_code == 401
    assert response.get_json()["message"] == "Token expired"


def test_users_service_down_gets_503(client, headers, monkeypatch):
    def service_down(authorization_header):
        raise auth.AuthServiceUnavailable()

    monkeypatch.setattr(auth, "verify_token", service_down)
    response = client.get(f"{ROUTE_PREFIX}/threats", headers=headers["admin"])

    assert response.status_code == 503
    assert response.get_json()["status"] == "error"


# Expected status code for every (endpoint, role) pair. 403 = role not allowed.
PERMISSION_MATRIX = {
    ("POST", f"{ROUTE_PREFIX}/threats"): {"admin": 201, "analyst": 403, "auditor": 403, "user": 403},
    ("GET", f"{ROUTE_PREFIX}/threats"): {"admin": 200, "analyst": 200, "auditor": 200, "user": 403},
    ("GET", f"{ROUTE_PREFIX}/threats/1"): {"admin": 200, "analyst": 200, "auditor": 200, "user": 403},
    ("GET", f"{ROUTE_PREFIX}/threats/search?severity=High"): {"admin": 200, "analyst": 200, "auditor": 200, "user": 403},
    ("PUT", f"{ROUTE_PREFIX}/threats/1"): {"admin": 200, "analyst": 403, "auditor": 403, "user": 403},
    ("DELETE", f"{ROUTE_PREFIX}/threats/1"): {"admin": 200, "analyst": 403, "auditor": 403, "user": 403},
}
REQUEST_BODIES = {"POST": DOMAIN_THREAT, "PUT": {"severity": "Critical"}}


@pytest.mark.parametrize(
    "method, url, role, expected_status",
    [
        (method, url, role, status)
        for (method, url), roles in PERMISSION_MATRIX.items()
        for role, status in roles.items()
    ],
)
def test_role_permissions(client, headers, audit_events, method, url, role, expected_status):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])  # becomes threat 1

    response = client.open(url, method=method, json=REQUEST_BODIES.get(method), headers=headers[role])

    assert response.status_code == expected_status
    if expected_status == 403:
        assert response.get_json()["message"] == "User does not have permission to perform this operation"
        assert audit_events[-1]["action"] == "PERMISSION_DENIED"


def test_analyst_cannot_delete_and_threat_survives(client, headers):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])

    response = client.delete(f"{ROUTE_PREFIX}/threats/1", headers=headers["analyst"])

    assert response.status_code == 403
    assert client.get(f"{ROUTE_PREFIX}/threats/1", headers=headers["admin"]).status_code == 200


# ---------- GET /threats and GET /threats/{id} ----------

def test_get_all_when_empty(client, headers):
    body = client.get(f"{ROUTE_PREFIX}/threats", headers=headers["admin"]).get_json()
    assert body["count"] == 0
    assert body["data"] == []


def test_get_all_returns_every_threat(client, headers, stored_threats):
    body = client.get(f"{ROUTE_PREFIX}/threats", headers=headers["analyst"]).get_json()

    assert body["count"] == 5
    assert [threat["threat_id"] for threat in body["data"]] == stored_threats
    assert set(body["data"][0]) == {
        "threat_id", "threat_type", "threat_value", "description", "severity", "source", "date_added",
    }


def test_get_existing_threat(client, headers, stored_threats):
    response = client.get(f"{ROUTE_PREFIX}/threats/{stored_threats[1]}", headers=headers["auditor"])

    assert response.status_code == 200
    assert response.get_json()["data"]["threat_value"] == "secure-bank-login.example"


def test_get_missing_threat_gets_404(client, headers):
    response = client.get(f"{ROUTE_PREFIX}/threats/999", headers=headers["admin"])

    assert response.status_code == 404
    assert response.get_json() == {"status": "error", "message": "Threat indicator with ID 999 not found"}


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_huge_id_gets_404_not_a_crash(client, headers, method):
    response = client.open(
        f"{ROUTE_PREFIX}/threats/99999999999999999999", method=method, json={"severity": "Low"}, headers=headers["admin"]
    )
    assert response.status_code == 404


def test_non_numeric_id_gets_json_404(client, headers):
    response = client.get(f"{ROUTE_PREFIX}/threats/abc", headers=headers["admin"])
    assert response.status_code == 404
    assert response.get_json()["status"] == "error"


# ---------- GET /threats/search ----------

@pytest.mark.parametrize(
    "query, expected_values",
    [
        ({"threat_type": "Domain"}, ["secure-bank-login.example"]),
        ({"severity": "Medium"}, ["Trojan.GenericKD.4614", "powershell -EncodedCommand"]),
        ({"source": "internal"}, ["Trojan.GenericKD.4614", "powershell -EncodedCommand"]),  # partial, any case
        ({"threat_value": "203.0.113"}, ["203.0.113.45"]),  # partial value
        ({"source": "Internal SOC", "severity": "Medium", "threat_type": "Other Indicators"}, ["powershell -EncodedCommand"]),
        ({"severity": "Critical", "source": "VirusTotal"}, []),  # valid search, no match
    ],
)
def test_search(client, headers, stored_threats, query, expected_values):
    response = client.get(f"{ROUTE_PREFIX}/threats/search", query_string=query, headers=headers["analyst"])

    assert response.status_code == 200
    assert [threat["threat_value"] for threat in response.get_json()["data"]] == expected_values


@pytest.mark.parametrize(
    "query, expected_error",
    [
        ("", "Provide at least one search parameter"),
        ("severty=High", "Unknown search parameter(s): severty"),
        ("severity=Extreme", "severity must be one of"),
        ("threat_type=URL", "threat_type must be one of"),
    ],
)
def test_invalid_search_is_rejected(client, headers, query, expected_error):
    response = client.get(f"{ROUTE_PREFIX}/threats/search?{query}", headers=headers["admin"])

    assert response.status_code == 400
    assert expected_error in response.get_json()["errors"][0]


def test_search_is_safe_from_sql_injection(client, headers, stored_threats, database_path):
    response = client.get(f"{ROUTE_PREFIX}/threats/search", query_string={"source": "' OR '1'='1"}, headers=headers["admin"])

    assert response.status_code == 200
    assert response.get_json()["count"] == 0  # treated as plain text, not as SQL
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 5


def test_search_wildcard_characters_are_matched_literally(client, headers, stored_threats):
    response = client.get(f"{ROUTE_PREFIX}/threats/search", query_string={"source": "%"}, headers=headers["admin"])
    assert response.get_json()["count"] == 0


# ---------- PUT /threats/{id} ----------

def test_admin_can_update_threat(client, headers, audit_events, database_path):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])

    response = client.put(
        f"{ROUTE_PREFIX}/threats/1",
        json={"severity": "Critical", "description": "Confirmed C2 server", "source": "CERT"},
        headers=headers["admin"],
    )

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert (data["severity"], data["description"], data["source"]) == ("Critical", "Confirmed C2 server", "CERT")
    assert data["threat_value"] == "203.0.113.45"  # unchanged
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT severity FROM threats WHERE threat_id = 1").fetchone()[0] == "Critical"
    assert audit_events[-1]["action"] == "UPDATE_THREAT"
    assert "severity: 'High' -> 'Critical'" in audit_events[-1]["description"]


def test_partial_update_keeps_other_fields(client, headers):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])

    data = client.put(f"{ROUTE_PREFIX}/threats/1", json={"severity": "Low"}, headers=headers["admin"]).get_json()["data"]

    assert data["severity"] == "Low"
    assert data["description"] == IP_THREAT["description"]


@pytest.mark.parametrize(
    "body, expected_error",
    [
        ({"threat_value": "198.51.100.7"}, "These fields cannot be updated: threat_value"),
        ({"threat_type": "Domain"}, "These fields cannot be updated: threat_type"),
        ({"severity": "Extreme"}, "severity must be one of"),
        ({"source": ""}, "source is required"),
        ({}, "Request body must be a non-empty JSON object"),
    ],
)
def test_invalid_update_is_rejected(client, headers, body, expected_error):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])

    response = client.put(f"{ROUTE_PREFIX}/threats/1", json=body, headers=headers["admin"])

    assert response.status_code == 400
    assert expected_error in response.get_json()["errors"][0]


def test_update_missing_threat_gets_404(client, headers):
    response = client.put(f"{ROUTE_PREFIX}/threats/999", json={"severity": "Low"}, headers=headers["admin"])
    assert response.status_code == 404


# ---------- DELETE /threats/{id} ----------

def test_admin_can_delete_threat(client, headers, audit_events, database_path):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])

    response = client.delete(f"{ROUTE_PREFIX}/threats/1", headers=headers["admin"])

    assert response.status_code == 200
    assert response.get_json()["message"] == "Threat indicator 1 deleted successfully"
    assert client.get(f"{ROUTE_PREFIX}/threats/1", headers=headers["admin"]).status_code == 404
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 0
    assert audit_events[-1]["action"] == "DELETE_THREAT"


def test_delete_missing_threat_gets_404(client, headers):
    assert client.delete(f"{ROUTE_PREFIX}/threats/999", headers=headers["admin"]).status_code == 404


def test_deleted_id_is_never_reused(client, headers):
    client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])
    client.delete(f"{ROUTE_PREFIX}/threats/1", headers=headers["admin"])

    response = client.post(f"{ROUTE_PREFIX}/threats", json=DOMAIN_THREAT, headers=headers["admin"])

    assert response.get_json()["data"]["threat_id"] == 2


# ---------- Threat alerts (notifications through Service 8) ----------

@pytest.mark.parametrize("threat", [IP_THREAT, DOMAIN_THREAT], ids=["High", "Critical"])
def test_high_and_critical_threats_alert_active_admins_and_analysts(client, headers, sent_notifications, threat):
    response = client.post(f"{ROUTE_PREFIX}/threats", json=threat, headers=headers["admin"])

    assert response.status_code == 201
    assert response.get_json()["message"] == "Threat indicator added successfully; threat alert sent to 3 user(s)"
    # Users 1 (admin), 2 and 5 (analysts). Not the employee, the auditor, or the suspended analyst 6.
    assert sorted(n["user_id"] for n in sent_notifications) == [1, 2, 5]
    alert = sent_notifications[0]
    assert alert["notification_type"] == "Threat Alert"
    assert alert["severity"] == threat["severity"]
    assert threat["threat_value"] in alert["title"]


@pytest.mark.parametrize("threat", [HASH_THREAT, SIGNATURE_THREAT], ids=["Low", "Medium"])
def test_low_and_medium_threats_send_no_alert(client, headers, sent_notifications, threat):
    response = client.post(f"{ROUTE_PREFIX}/threats", json=threat, headers=headers["admin"])

    assert response.get_json()["message"] == "Threat indicator added successfully"
    assert sent_notifications == []


def test_threat_is_still_saved_when_users_service_is_down(client, headers, sent_notifications, monkeypatch):
    def users_down(authorization_header):
        raise users_client.UsersServiceUnavailable()

    monkeypatch.setattr(users_client, "list_users", users_down)
    response = client.post(f"{ROUTE_PREFIX}/threats", json=IP_THREAT, headers=headers["admin"])

    assert response.status_code == 201
    assert response.get_json()["message"].endswith("threat alert sent to 0 user(s)")
    assert client.get(f"{ROUTE_PREFIX}/threats/1", headers=headers["admin"]).status_code == 200


# ---------- Errors outside our routes still use the JSON format ----------

def test_wrong_method_gets_json_405(client, headers):
    response = client.patch(f"{ROUTE_PREFIX}/threats/1", headers=headers["admin"])
    assert response.status_code == 405
    assert response.get_json()["status"] == "error"


def test_route_without_student_name_does_not_exist(client, headers):
    assert ROUTE_PREFIX == "/sleiman-koumaira"
    response = client.get("/threats", headers=headers["admin"])
    assert response.status_code == 404


def test_unknown_url_gets_json_404(client):
    response = client.get("/threatz")
    assert response.status_code == 404
    assert response.get_json()["status"] == "error"
