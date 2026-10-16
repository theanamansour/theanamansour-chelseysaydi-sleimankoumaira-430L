"""Service 6 (Security Reports) tests - Theana Mansour.

Run from the repository root:  python -m pytest -q tests/test_report_service.py

Each test gets a temporary shared database filled with known records, so every
report number can be checked exactly. Service 1 token checks and Service 5
audit calls are replaced with fakes, so no other service needs to be running.
"""
import pytest
import requests

from database.connection import get_db
from database.init_db import init_database
from services.reports import audit_client
from services.reports import auth as auth_module
from services.reports.app import ROUTE_PREFIX, create_app
from services.reports.auth import ADMIN, ANALYST, AUDITOR, EMPLOYEE
from services.reports.sample_data import load_sample_data

REPORTS = ("summary", "incidents", "assets", "threats", "vulnerabilities", "activity")
IDENTITIES = {
    "admin": {"valid": True, "user_id": 1, "username": "admin", "role": ADMIN},
    "analyst": {"valid": True, "user_id": 2, "username": "analyst", "role": ANALYST},
    "employee": {"valid": True, "user_id": 3, "username": "employee", "role": EMPLOYEE},
    "auditor": {"valid": True, "user_id": 4, "username": "auditor", "role": AUDITOR},
}


def seed(path):
    """Known data: 5 users, 4 assets, 5 incidents, 6 threats, 4 vulnerabilities, 9 logs."""
    init_database(database_path=path)
    with get_db(path) as db:
        db.executemany(
            "INSERT INTO users (id, full_name, username, email, password_hash, "
            "department, role, account_status) VALUES (?, ?, ?, ?, 'x', 'IT', ?, ?)",
            [
                (1, "Admin", "admin", "admin@example.com", ADMIN, "Active"),
                (2, "Analyst", "analyst", "analyst@example.com", ANALYST, "Active"),
                (3, "Employee", "employee", "employee@example.com", EMPLOYEE, "Active"),
                (4, "Auditor", "auditor", "auditor@example.com", AUDITOR, "Active"),
                (5, "Old", "old", "old@example.com", EMPLOYEE, "Suspended"),
            ],
        )
        db.executemany(
            "INSERT INTO assets (asset_id, asset_name, asset_type, ip_address, "
            "owner_id, department, criticality, status) VALUES (?, ?, ?, ?, 1, 'IT', ?, ?)",
            [
                (1, "Web", "Server", "10.0.0.1", "Critical", "Active"),
                (2, "DB", "Database", "10.0.0.2", "Critical", "Active"),
                (3, "Laptop", "Workstation", "10.0.0.3", "Low", "Inactive"),
                (4, "Router", "Network Device", "10.0.0.4", "High", "Under Maintenance"),
            ],
        )
        db.executemany(
            "INSERT INTO incidents (incident_id, title, description, category, "
            "severity, reporter_id, asset_id, assigned_analyst_id, status, created_at) "
            "VALUES (?, ?, 'd', 'c', ?, 3, ?, ?, ?, ?)",
            [
                (1, "I1", "Critical", 1, 2, "Open", "2026-10-01 10:00:00"),
                (2, "I2", "High", 2, None, "Under Investigation", "2026-10-02 10:00:00"),
                (3, "I3", "High", 1, None, "Open", "2026-10-03 10:00:00"),
                (4, "I4", "Low", 3, 2, "Resolved", "2026-10-04 10:00:00"),
                (5, "I5", "Medium", 4, 2, "Closed", "2026-10-05 10:00:00"),
            ],
        )
        db.executemany(
            "INSERT INTO threats (threat_id, threat_type, threat_value, description, "
            "severity, source, date_added) VALUES (?, ?, ?, 'd', ?, 'feed', ?)",
            [
                (1, "IP Address", "203.0.113.1", "Critical", "2026-10-01 09:00:00"),
                (2, "IP Address", "203.0.113.2", "High", "2026-10-02 09:00:00"),
                (3, "Domain", "bad.example", "Critical", "2026-10-03 09:00:00"),
                (4, "File Hash", "abc123", "Medium", "2026-10-04 09:00:00"),
                (5, "Malware Signature", "Trojan.X", "Low", "2026-10-05 09:00:00"),
                (6, "Domain", "worse.example", "High", "2026-10-06 09:00:00"),
            ],
        )
        db.executemany(
            "INSERT INTO vulnerabilities (vulnerability_id, vulnerability_title, "
            "description, cve_identifier, cvss_score, severity, affected_asset_id, "
            "discovery_source, status) VALUES (?, ?, 'd', ?, ?, ?, ?, 'scan', ?)",
            [
                (1, "V1", "CVE-2021-44228", 10.0, "Critical", 1, "Open"),
                (2, "V2", "CVE-2024-6387", 8.1, "High", 1, "In Progress"),
                (3, "V3", "CVE-2020-0796", 9.8, "Critical", 2, "Resolved"),
                (4, "V4", "CVE-2011-3389", 4.1, "Medium", 4, "Closed"),
            ],
        )
        db.executemany(
            "INSERT INTO audit_logs (log_id, user_id, action, description, severity, "
            "related_service, timestamp) VALUES (?, ?, ?, 'd', ?, 'svc', ?)",
            [
                (1, 1, "LOGIN_SUCCESS", "Information", "2026-10-10 08:00:00"),
                (2, 3, "LOGIN_SUCCESS", "Information", "2026-10-10 08:05:00"),
                (3, 4, "LOGIN_SUCCESS", "Information", "2026-10-10 08:10:00"),
                (4, None, "LOGIN_FAILED", "Warning", "2026-10-10 08:15:00"),
                (5, None, "LOGIN_FAILED", "Warning", "2026-10-10 08:16:00"),
                (6, 5, "LOGIN_BLOCKED", "Warning", "2026-10-10 08:20:00"),
                (7, 3, "PERMISSION_DENIED", "Warning", "2026-10-10 08:30:00"),
                (8, 1, "REGISTER_USER", "Information", "2026-10-10 08:40:00"),
                (9, 1, "DELETE_USER", "Critical", "2026-10-10 08:50:00"),
            ],
        )


@pytest.fixture
def audit_events(monkeypatch):
    events = []
    monkeypatch.setattr(
        audit_client, "send_audit_log",
        lambda *args, **kwargs: events.append(args) or True,
    )
    return events


@pytest.fixture
def database_path(tmp_path):
    path = tmp_path / "security_system.db"
    seed(path)
    return path


@pytest.fixture
def client(database_path, monkeypatch, audit_events):
    def verify(authorization):
        identity = IDENTITIES.get(authorization.removeprefix("Bearer ").strip())
        if identity is None:
            return None, auth_module.error("Invalid token", 401)
        return identity, None

    monkeypatch.setattr(auth_module, "verify_identity", verify)
    return create_app(database_path).test_client()


def get(client, report, role=None, query=""):
    headers = {"Authorization": f"Bearer {role}"} if role else {}
    return client.get(f"{ROUTE_PREFIX}/{report}{query}", headers=headers)


# ---------- access control ----------

@pytest.mark.parametrize("report", REPORTS)
@pytest.mark.parametrize("role,status", [
    ("admin", 200), ("auditor", 200), ("analyst", 403), ("employee", 403),
])
def test_role_access(client, report, role, status):
    response = get(client, report, role)
    assert response.status_code == status
    if status == 403:
        assert response.get_json() == {
            "status": "error",
            "message": "User does not have permission to perform this operation",
        }


@pytest.mark.parametrize("report", REPORTS)
def test_missing_and_invalid_tokens(client, report):
    assert get(client, report).status_code == 401
    assert get(client, report, "not-a-token").status_code == 401
    response = client.get(f"{ROUTE_PREFIX}/{report}", headers={"Authorization": "Basic abc"})
    assert response.status_code == 401


def test_denials_and_reports_are_audited(client, audit_events):
    get(client, "summary")
    get(client, "summary", "employee")
    get(client, "summary", "auditor")
    actions = [event[1] for event in audit_events]
    assert actions == ["UNAUTHENTICATED_ACCESS", "PERMISSION_DENIED", "GENERATE_REPORT"]
    assert audit_events[1][0] == 3  # the employee's user id
    assert audit_events[2][0] == 4  # the auditor's user id


# ---------- response format ----------

def test_success_envelope(client):
    body = get(client, "summary", "auditor").get_json()
    assert body["status"] == "success"
    assert body["report"] == "summary"
    assert body["message"] == "Security summary report generated successfully"
    assert body["generated_by"] == {"user_id": 4, "username": "auditor", "role": AUDITOR}
    assert len(body["generated_at"]) == 19


# ---------- report values match the database ----------

def test_summary_report(client):
    data = get(client, "summary", "admin").get_json()["data"]
    assert data["users"] == 5
    assert data["active_users"] == 4
    assert data["assets"] == 4
    assert data["critical_assets"] == 2
    assert data["incidents"] == 5
    assert data["open_incidents"] == 3
    assert data["incidents_by_severity"] == {"Low": 1, "Medium": 1, "High": 2, "Critical": 1}
    assert data["threats"] == 6
    assert data["critical_threats"] == 2
    assert data["vulnerabilities"] == 4
    assert data["open_vulnerabilities"] == 2
    assert data["audit_records"] == 9
    assert [row["log_id"] for row in data["recent_activities"]] == [9, 8, 7, 6, 5]


def test_incident_report(client):
    data = get(client, "incidents", "admin").get_json()["data"]
    assert data["total_incidents"] == 5
    assert data["open_incidents"] == 3
    assert data["unassigned_open_incidents"] == 2
    assert data["by_severity"] == {"Low": 1, "Medium": 1, "High": 2, "Critical": 1}
    assert data["by_status"] == {
        "Open": 2, "Under Investigation": 1, "Mitigated": 0, "Resolved": 1, "Closed": 1,
    }
    assert [row["incident_id"] for row in data["recent_incidents"]] == [5, 4, 3, 2, 1]


def test_asset_report(client):
    data = get(client, "assets", "auditor").get_json()["data"]
    assert data["total_assets"] == 4
    assert data["critical_assets"] == 2
    assert data["by_type"] == {
        "Server": 1, "Workstation": 1, "Database": 1, "Application": 0,
        "Network Device": 1, "Cloud Resource": 0,
    }
    assert data["by_criticality"] == {"Low": 1, "Medium": 0, "High": 1, "Critical": 2}
    assert data["by_status"] == {"Active": 2, "Inactive": 1, "Under Maintenance": 1}
    assert {row["asset_name"] for row in data["critical_asset_list"]} == {"Web", "DB"}


def test_threat_report(client):
    data = get(client, "threats", "admin").get_json()["data"]
    assert data["total_threats"] == 6
    assert data["critical_threats"] == 2
    assert data["by_severity"] == {"Low": 1, "Medium": 1, "High": 2, "Critical": 2}
    assert data["by_type"] == {
        "IP Address": 2, "Domain": 2, "File Hash": 1,
        "Malware Signature": 1, "Other Indicators": 0,
    }
    assert [row["threat_id"] for row in data["recent_threats"]] == [6, 5, 4, 3, 2]


def test_vulnerability_report(client):
    data = get(client, "vulnerabilities", "admin").get_json()["data"]
    assert data["total_vulnerabilities"] == 4
    assert data["open_vulnerabilities"] == 2
    assert data["critical_vulnerabilities"] == 2
    assert data["average_cvss_score"] == 8.0
    assert data["by_severity"] == {"Low": 0, "Medium": 1, "High": 1, "Critical": 2}
    assert data["by_status"] == {
        "Open": 1, "Under Investigation": 0, "In Progress": 1, "Resolved": 1, "Closed": 1,
    }
    assert [row["vulnerability_id"] for row in data["critical_vulnerability_list"]] == [1, 3]


def test_activity_report(client):
    data = get(client, "activity", "auditor").get_json()["data"]
    assert data["total_activities"] == 9
    assert data["active_users"] == 4
    assert data["login_attempts"] == 6
    assert data["successful_logins"] == 3
    assert data["failed_logins"] == 2
    assert data["blocked_logins"] == 1
    assert data["permission_denied"] == 1
    assert data["by_severity"] == {"Information": 4, "Warning": 4, "Error": 0, "Critical": 1}
    assert data["most_performed_actions"][:2] == [
        {"action": "LOGIN_SUCCESS", "count": 3},
        {"action": "LOGIN_FAILED", "count": 2},
    ]
    assert len(data["recent_activities"]) == 5


def test_empty_database_gives_zero_reports(tmp_path, monkeypatch, audit_events):
    monkeypatch.setattr(auth_module, "verify_identity", lambda a: (IDENTITIES["admin"], None))
    client = create_app(tmp_path / "empty.db").test_client()
    data = get(client, "vulnerabilities", "admin").get_json()["data"]
    assert data["total_vulnerabilities"] == 0
    assert data["average_cvss_score"] is None
    assert data["by_status"]["Open"] == 0
    activity = get(client, "activity", "admin").get_json()["data"]
    assert activity["most_performed_actions"] == []
    assert activity["recent_activities"] == []


# ---------- validation ----------

@pytest.mark.parametrize("query,expected", [
    ("?limit=2", 2), ("?limit=1", 1), ("?limit=50", 6),
])
def test_limit_controls_list_size(client, query, expected):
    data = get(client, "threats", "admin", query).get_json()["data"]
    assert len(data["recent_threats"]) == expected


@pytest.mark.parametrize("query", [
    "?limit=0", "?limit=51", "?limit=-1", "?limit=abc", "?limit=2.5", "?limit=",
    "?limit=1%27%20OR%20%271%27=%271", "?days=7",
])
def test_invalid_query_parameters(client, query):
    response = get(client, "summary", "admin", query)
    assert response.status_code == 400
    assert response.get_json()["message"] == "Validation failed"


def test_reports_are_read_only(client, database_path):
    with get_db(database_path) as db:
        before = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    for report in REPORTS:
        get(client, report, "admin")
    with get_db(database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == before


def test_unknown_route_and_method(client):
    assert get(client, "nothing", "admin").status_code == 404
    assert client.post(f"{ROUTE_PREFIX}/summary").status_code == 405


# ---------- talking to Service 1 ----------

class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.content = b"x"

    def json(self):
        return self._payload


def real_auth_client(tmp_path, monkeypatch, fake_post):
    monkeypatch.setattr(auth_module.requests, "post", fake_post)
    monkeypatch.setattr(audit_client, "send_audit_log", lambda *a, **k: True)
    path = tmp_path / "db.db"
    seed(path)
    return create_app(path).test_client()


def test_service1_verify_is_called_with_the_token(tmp_path, monkeypatch):
    calls = []

    def fake_post(url, headers, timeout):
        calls.append((url, headers["Authorization"]))
        return FakeResponse(200, IDENTITIES["auditor"])

    client = real_auth_client(tmp_path, monkeypatch, fake_post)
    assert get(client, "summary", "abc.def.ghi").status_code == 200
    assert calls == [(f"{auth_module.USER_SERVICE_URL}/auth/verify", "Bearer abc.def.ghi")]


def test_service1_rejection_is_passed_on(tmp_path, monkeypatch):
    client = real_auth_client(
        tmp_path, monkeypatch,
        lambda url, headers, timeout: FakeResponse(401, {"valid": False, "message": "Token expired"}),
    )
    response = get(client, "summary", "old.token.here")
    assert response.status_code == 401
    assert response.get_json()["message"] == "Token expired"


def test_service1_down_returns_503(tmp_path, monkeypatch):
    def fake_post(url, headers, timeout):
        raise requests.ConnectionError("refused")

    client = real_auth_client(tmp_path, monkeypatch, fake_post)
    response = get(client, "summary", "abc")
    assert response.status_code == 503
    assert response.get_json()["message"] == "User service is unavailable"


def test_audit_failure_never_breaks_a_report(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_module, "verify_identity", lambda a: (IDENTITIES["admin"], None))
    monkeypatch.setattr(audit_client, "AUDIT_LOG_URL", "http://127.0.0.1:9/chelsea-saydi/logs")
    monkeypatch.setenv("INTERNAL_SERVICE_KEY", "test-key")
    monkeypatch.delenv("AUDIT_LOG_DISABLED", raising=False)
    path = tmp_path / "db.db"
    seed(path)
    assert get(create_app(path).test_client(), "summary", "admin").status_code == 200


# ---------- sample data loader ----------

def test_sample_data_loads_once(tmp_path):
    path = tmp_path / "sample.db"
    init_database(database_path=path)
    assert "No active Security Administrator" in load_sample_data(path)
    with get_db(path) as db:
        db.execute(
            "INSERT INTO users (full_name, username, email, password_hash, department, role) "
            "VALUES ('A', 'admin', 'a@example.com', 'x', 'IT', 'Security Administrator')"
        )
    assert load_sample_data(path).startswith("Inserted 6 assets, 6 incidents, 7 threats")
    assert "already loaded" in load_sample_data(path)
    with get_db(path) as db:
        assert db.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 7
        assert db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0] == 6
