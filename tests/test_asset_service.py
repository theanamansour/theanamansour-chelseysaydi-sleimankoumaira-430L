"""Automated tests for Service 2 - Asset Management Service (Sleiman Koumaira)."""
import sqlite3

import pytest

from database.init_db import init_database
from services.assets.app import ROUTE_PREFIX, create_app
from shared import auth, users_client
from tests.conftest import add_test_users

URL = f"{ROUTE_PREFIX}/assets"

# Test data uses reserved documentation IP ranges (192.0.2.x, 198.51.100.x, 203.0.113.x).
WEB_SERVER = {
    "asset_name": "Main Web Server",
    "asset_type": "Server",
    "ip_address": "192.0.2.10",
    "operating_system": "Ubuntu 22.04",
    "owner_id": 1,
    "department": "IT",
    "location": "Beirut Data Center",
    "criticality": "Critical",
}
HR_LAPTOP = {
    "asset_name": "HR Laptop 07",
    "asset_type": "Workstation",
    "ip_address": "192.0.2.57",
    "operating_system": "Windows 11",
    "owner_id": 3,
    "department": "Human Resources",
    "location": "Floor 2",
    "criticality": "Low",
}
CUSTOMER_DB = {
    "asset_name": "Customer Database",
    "asset_type": "Database",
    "ip_address": "198.51.100.20",
    "operating_system": "Red Hat Enterprise Linux 9",
    "owner_id": 1,
    "department": "IT",
    "location": "Beirut Data Center",
    "criticality": "High",
    "status": "Under Maintenance",
}
PAYROLL_APP = {
    "asset_name": "Payroll Application",
    "asset_type": "Application",
    "ip_address": "198.51.100.35",
    "owner_id": 2,
    "department": "Finance",
    "criticality": "High",
}
CORE_ROUTER = {
    "asset_name": "Core Router",
    "asset_type": "Network Device",
    "ip_address": "192.0.2.1",
    "operating_system": "Cisco IOS XE",
    "owner_id": 1,
    "department": "IT",
    "location": "Server Room A",
    "criticality": "Critical",
}
CLOUD_STORAGE = {
    "asset_name": "Backup Cloud Storage",
    "asset_type": "Cloud Resource",
    "ip_address": "2001:db8::25",
    "owner_id": 2,
    "department": "Finance",
    "location": "AWS eu-central-1",
    "criticality": "Medium",
    "status": "Inactive",
}
ALL_ASSETS = [WEB_SERVER, HR_LAPTOP, CUSTOMER_DB, PAYROLL_APP, CORE_ROUTER, CLOUD_STORAGE]


@pytest.fixture
def database_path(tmp_path):
    """A brand-new copy of the shared database for every test, so tests never touch the real data."""
    path = init_database("assets", str(tmp_path / "security_system.db"))
    add_test_users(path)
    return path


@pytest.fixture
def client(database_path):
    """A test client that sends the Security Administrator's token unless a test sends another one."""
    test_client = create_app(database_path).test_client()
    test_client.environ_base["HTTP_AUTHORIZATION"] = "Bearer admin-token"
    return test_client


@pytest.fixture
def stored_assets(client):
    """Insert the six sample assets and return their IDs."""
    ids = []
    for asset in ALL_ASSETS:
        response = client.post(URL, json=asset)
        assert response.status_code == 201
        ids.append(response.get_json()["data"]["asset_id"])
    return ids


# ---------- POST /assets ----------

@pytest.mark.parametrize("asset", ALL_ASSETS, ids=lambda a: a["asset_type"])
def test_add_every_asset_type(client, asset):
    response = client.post(URL, json=asset)

    assert response.status_code == 201
    body = response.get_json()
    assert body["status"] == "success"
    assert body["message"] == "Asset added successfully"
    for field, value in asset.items():
        assert body["data"][field] == value
    assert isinstance(body["data"]["asset_id"], int)


def test_status_defaults_to_active_and_optional_fields_can_be_left_out(client):
    data = client.post(URL, json=PAYROLL_APP).get_json()["data"]

    assert data["status"] == "Active"
    assert data["operating_system"] is None
    assert data["location"] is None


def test_added_asset_is_stored_in_database(client, database_path):
    client.post(URL, json=WEB_SERVER)

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT asset_name, asset_type, ip_address, owner_id, criticality, status FROM assets"
        ).fetchone()
    assert row == ("Main Web Server", "Server", "192.0.2.10", 1, "Critical", "Active")


def test_ip_address_is_stored_in_standard_form(client):
    data = client.post(URL, json={**CLOUD_STORAGE, "ip_address": "2001:DB8:0:0:0:0:0:25"}).get_json()["data"]
    assert data["ip_address"] == "2001:db8::25"


@pytest.mark.parametrize(
    "changes, expected_error",
    [
        ({"ip_address": "999.1.1.1"}, "not a valid IPv4 or IPv6 address"),
        ({"ip_address": "192.168.1"}, "not a valid IPv4 or IPv6 address"),
        ({"ip_address": "not-an-ip"}, "not a valid IPv4 or IPv6 address"),
        ({"asset_type": "Printer"}, "asset_type must be one of"),
        ({"asset_type": "server"}, "asset_type must be one of"),
        ({"criticality": "Extreme"}, "criticality must be one of"),
        ({"status": "Broken"}, "status must be one of"),
        ({"asset_name": "   "}, "asset_name is required"),
        ({"department": 42}, "department must be text"),
        ({"owner_id": 0}, "owner_id must be a positive whole number"),
        ({"owner_id": -5}, "owner_id must be a positive whole number"),
        ({"owner_id": "1"}, "owner_id must be a positive whole number"),
        ({"owner_id": 1.5}, "owner_id must be a positive whole number"),
        ({"owner_id": True}, "owner_id must be a positive whole number"),
        ({"operating_system": ""}, "operating_system cannot be blank"),
        ({"location": "x" * 101}, "location must be at most 100 characters"),
        ({"serial_number": "ABC123"}, "Unknown field(s): serial_number"),
    ],
)
def test_invalid_input_is_rejected(client, database_path, changes, expected_error):
    response = client.post(URL, json={**WEB_SERVER, **changes})

    assert response.status_code == 400
    body = response.get_json()
    assert body["status"] == "error"
    assert body["message"] == "Validation failed"
    assert any(expected_error in error for error in body["errors"])
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0


def test_missing_required_fields_are_all_reported(client):
    response = client.post(URL, json={"asset_name": "Lonely Asset"})

    assert response.status_code == 400
    errors = response.get_json()["errors"]
    for field in ("asset_type", "ip_address", "department", "owner_id", "criticality"):
        assert f"{field} is required" in errors


@pytest.mark.parametrize(
    "request_options",
    [{"data": ""}, {"data": "not json", "content_type": "text/plain"}, {"json": []}, {"json": {}}],
    ids=["empty body", "plain text", "JSON list", "empty object"],
)
def test_empty_or_non_json_body_is_rejected(client, request_options):
    response = client.post(URL, **request_options)

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["Request body must be a non-empty JSON object"]


# ---------- GET /assets and GET /assets/{id} ----------

def test_get_all_when_empty(client):
    body = client.get(URL).get_json()
    assert body == {"status": "success", "count": 0, "data": []}


def test_get_all_returns_every_asset_with_criticality_and_status(client, stored_assets):
    body = client.get(URL).get_json()

    assert body["count"] == 6
    assert [asset["asset_id"] for asset in body["data"]] == stored_assets
    assert set(body["data"][0]) == {
        "asset_id", "asset_name", "asset_type", "ip_address", "operating_system", "owner_id",
        "department", "location", "criticality", "status",
    }


def test_get_existing_asset(client, stored_assets):
    response = client.get(f"{URL}/{stored_assets[2]}")

    assert response.status_code == 200
    assert response.get_json()["data"]["asset_name"] == "Customer Database"


def test_get_missing_asset_gets_404(client):
    response = client.get(f"{URL}/999")

    assert response.status_code == 404
    assert response.get_json() == {"status": "error", "message": "Asset with ID 999 not found"}


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_huge_id_gets_404_not_a_crash(client, method):
    response = client.open(f"{URL}/99999999999999999999", method=method, json={"status": "Inactive"})
    assert response.status_code == 404


def test_non_numeric_id_gets_json_404(client):
    response = client.get(f"{URL}/abc")
    assert response.status_code == 404
    assert response.get_json()["status"] == "error"


# ---------- GET /assets/search ----------

@pytest.mark.parametrize(
    "query, expected_names",
    [
        ({"asset_name": "server"}, ["Main Web Server"]),  # partial, any case
        ({"asset_type": "Database"}, ["Customer Database"]),
        ({"ip_address": "192.0.2."}, ["Main Web Server", "HR Laptop 07", "Core Router"]),  # partial IP (subnet)
        ({"department": "finance"}, ["Payroll Application", "Backup Cloud Storage"]),  # partial, any case
        ({"criticality": "Critical"}, ["Main Web Server", "Core Router"]),
        ({"department": "IT", "criticality": "High"}, ["Customer Database"]),  # combined with AND
        ({"asset_type": "Server", "criticality": "Low"}, []),  # valid search, no match
    ],
)
def test_search(client, stored_assets, query, expected_names):
    response = client.get(f"{URL}/search", query_string=query)

    assert response.status_code == 200
    assert [asset["asset_name"] for asset in response.get_json()["data"]] == expected_names


@pytest.mark.parametrize(
    "query, expected_error",
    [
        ({}, "Provide at least one search parameter"),
        ({"criticallity": "High"}, "Unknown search parameter(s): criticallity"),
        ({"criticality": "Extreme"}, "criticality must be one of"),
        ({"asset_type": "Printer"}, "asset_type must be one of"),
    ],
)
def test_invalid_search_is_rejected(client, query, expected_error):
    response = client.get(f"{URL}/search", query_string=query)

    assert response.status_code == 400
    assert expected_error in response.get_json()["errors"][0]


def test_search_is_safe_from_sql_injection(client, stored_assets, database_path):
    response = client.get(f"{URL}/search", query_string={"department": "' OR '1'='1"})

    assert response.status_code == 200
    assert response.get_json()["count"] == 0
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 6


def test_search_wildcard_characters_are_matched_literally(client, stored_assets):
    response = client.get(f"{URL}/search", query_string={"asset_name": "%"})
    assert response.get_json()["count"] == 0


# ---------- PUT /assets/{id} ----------

def test_update_all_allowed_fields(client, database_path):
    client.post(URL, json=WEB_SERVER)

    response = client.put(
        f"{URL}/1",
        json={
            "asset_name": "Main Web Server (Primary)",
            "owner_id": 2,
            "department": "Security Operations",
            "criticality": "High",
            "status": "Under Maintenance",
        },
    )

    assert response.status_code == 200
    assert response.get_json()["message"] == "Asset information updated successfully"
    data = response.get_json()["data"]
    assert (data["asset_name"], data["owner_id"], data["department"], data["criticality"], data["status"]) == (
        "Main Web Server (Primary)", 2, "Security Operations", "High", "Under Maintenance",
    )
    assert data["ip_address"] == "192.0.2.10"  # not updatable, unchanged
    with sqlite3.connect(database_path) as connection:
        row = connection.execute("SELECT status, criticality FROM assets WHERE asset_id = 1").fetchone()
    assert row == ("Under Maintenance", "High")


def test_partial_update_keeps_other_fields(client):
    client.post(URL, json=WEB_SERVER)

    data = client.put(f"{URL}/1", json={"status": "Inactive"}).get_json()["data"]

    assert data["status"] == "Inactive"
    assert data["criticality"] == "Critical"
    assert data["asset_name"] == "Main Web Server"


@pytest.mark.parametrize(
    "body, expected_error",
    [
        ({"ip_address": "192.0.2.99"}, "These fields cannot be updated: ip_address"),
        ({"asset_type": "Workstation"}, "These fields cannot be updated: asset_type"),
        ({"criticality": "Extreme"}, "criticality must be one of"),
        ({"status": "Retired"}, "status must be one of"),
        ({"owner_id": "two"}, "owner_id must be a positive whole number"),
        ({"asset_name": ""}, "asset_name is required"),
        ({"status": None}, "status is required"),
        ({}, "Request body must be a non-empty JSON object"),
    ],
)
def test_invalid_update_is_rejected(client, body, expected_error):
    client.post(URL, json=WEB_SERVER)

    response = client.put(f"{URL}/1", json=body)

    assert response.status_code == 400
    assert expected_error in response.get_json()["errors"][0]


def test_update_missing_asset_gets_404(client):
    response = client.put(f"{URL}/999", json={"status": "Inactive"})
    assert response.status_code == 404
    assert response.get_json()["message"] == "Asset with ID 999 not found"


# ---------- DELETE /assets/{id} ----------

def test_delete_asset(client, database_path):
    client.post(URL, json=WEB_SERVER)

    response = client.delete(f"{URL}/1")

    assert response.status_code == 200
    assert response.get_json() == {"status": "success", "message": "Asset 1 deleted successfully"}
    assert client.get(f"{URL}/1").status_code == 404
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0


def test_delete_missing_asset_gets_404(client):
    assert client.delete(f"{URL}/999").status_code == 404


def test_deleted_id_is_never_reused(client):
    client.post(URL, json=WEB_SERVER)
    client.delete(f"{URL}/1")

    response = client.post(URL, json=HR_LAPTOP)

    assert response.get_json()["data"]["asset_id"] == 2


# ---------- Owner must be a real user of Service 1 ----------

def test_owner_that_does_not_exist_is_rejected(client, database_path):
    response = client.post(URL, json={**WEB_SERVER, "owner_id": 99})

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["owner_id 99 does not match any registered user"]
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0


def test_update_to_an_owner_that_does_not_exist_is_rejected(client):
    client.post(URL, json=WEB_SERVER)

    response = client.put(f"{URL}/1", json={"owner_id": 99})

    assert response.status_code == 400
    assert client.get(f"{URL}/1").get_json()["data"]["owner_id"] == 1


def test_owner_check_needs_users_service(client, monkeypatch):
    def users_down(authorization_header):
        raise users_client.UsersServiceUnavailable()

    monkeypatch.setattr(users_client, "list_users", users_down)
    response = client.post(URL, json=WEB_SERVER)

    assert response.status_code == 503
    assert "Service 1" in response.get_json()["message"]


# ---------- Authentication (401) and authorization (403) ----------

ENDPOINTS = [
    ("POST", URL),
    ("GET", URL),
    ("GET", f"{URL}/1"),
    ("GET", f"{URL}/search?criticality=Critical"),
    ("PUT", f"{URL}/1"),
    ("DELETE", f"{URL}/1"),
]


@pytest.mark.parametrize("method, url", ENDPOINTS)
def test_request_without_token_gets_401(database_path, audit_events, method, url):
    anonymous = create_app(database_path).test_client()

    response = anonymous.open(url, method=method, json={})

    assert response.status_code == 401
    assert audit_events[-1]["action"] == "UNAUTHENTICATED_ACCESS"


def test_invalid_token_gets_401(client):
    response = client.get(URL, headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401
    assert response.get_json()["message"] == "Invalid token"


def test_users_service_down_gets_503(client, monkeypatch):
    def service_down(authorization_header):
        raise auth.AuthServiceUnavailable()

    monkeypatch.setattr(auth, "verify_token", service_down)
    assert client.get(URL).status_code == 503


# Expected status code for every (endpoint, role) pair. 403 = role not allowed.
PERMISSION_MATRIX = {
    ("POST", URL): {"admin": 201, "analyst": 403, "auditor": 403, "user": 403},
    ("GET", URL): {"admin": 200, "analyst": 403, "auditor": 200, "user": 403},
    ("GET", f"{URL}/1"): {"admin": 200, "analyst": 200, "auditor": 200, "user": 403},
    ("GET", f"{URL}/search?criticality=Critical"): {"admin": 200, "analyst": 200, "auditor": 200, "user": 403},
    ("PUT", f"{URL}/1"): {"admin": 200, "analyst": 403, "auditor": 403, "user": 403},
    ("DELETE", f"{URL}/1"): {"admin": 200, "analyst": 403, "auditor": 403, "user": 403},
}
REQUEST_BODIES = {"POST": HR_LAPTOP, "PUT": {"status": "Inactive"}}


@pytest.mark.parametrize(
    "method, url, role, expected_status",
    [
        (method, url, role, status)
        for (method, url), roles in PERMISSION_MATRIX.items()
        for role, status in roles.items()
    ],
)
def test_role_permissions(client, headers, audit_events, method, url, role, expected_status):
    client.post(URL, json=WEB_SERVER)  # becomes asset 1 (added by the admin)

    response = client.open(url, method=method, json=REQUEST_BODIES.get(method), headers=headers[role])

    assert response.status_code == expected_status
    if expected_status == 403:
        assert response.get_json()["message"] == "User does not have permission to perform this operation"
        assert audit_events[-1]["action"] == "PERMISSION_DENIED"


def test_analyst_cannot_delete_and_asset_survives(client, headers):
    client.post(URL, json=WEB_SERVER)

    assert client.delete(f"{URL}/1", headers=headers["analyst"]).status_code == 403
    assert client.get(f"{URL}/1").status_code == 200


# ---------- Automatic audit logs (Service 5) ----------

def test_changes_are_sent_to_the_audit_log(client, audit_events):
    client.post(URL, json=WEB_SERVER)
    client.put(f"{URL}/1", json={"criticality": "High"})
    client.delete(f"{URL}/1")

    actions = [(event["action"], event["severity"], event["user_id"]) for event in audit_events]
    assert actions == [
        ("CREATE_ASSET", "Information", 1),
        ("UPDATE_ASSET", "Information", 1),
        ("DELETE_ASSET", "Warning", 1),
    ]
    assert "criticality: 'Critical' -> 'High'" in audit_events[1]["description"]
    assert all(event["related_service"] == "Asset Management Service" for event in audit_events)


# ---------- Routes and errors outside our routes ----------

def test_route_without_student_name_does_not_exist(client):
    assert ROUTE_PREFIX == "/sleiman-koumaira"
    assert client.get("/assets").status_code == 404


def test_wrong_method_gets_json_405(client):
    response = client.patch(f"{URL}/1")
    assert response.status_code == 405
    assert response.get_json()["status"] == "error"


def test_database_rejects_invalid_values_even_without_the_api(database_path):
    """The CHECK rules in 02_assets.sql are a second layer of protection behind validation.py."""
    with sqlite3.connect(database_path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO assets (asset_name, asset_type, ip_address, owner_id, department, criticality) "
            "VALUES ('X', 'Server', '192.0.2.1', 1, 'IT', 'Extreme')"
        )
