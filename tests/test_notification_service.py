"""Automated tests for Service 8 - Notification and Alert Management Service (Sleiman Koumaira)."""
import sqlite3
from datetime import datetime, timezone

import pytest

from database.init_db import init_database
from services.notifications.app import ROUTE_PREFIX, create_app
from services.notifications.repository import NotificationRepository
from shared import config, users_client
from tests.conftest import add_test_users

URL = f"{ROUTE_PREFIX}/notifications"

# Test users (see conftest.py): 1 admin, 2 analyst, 3 regular employee, 4 auditor, 5 second analyst.
INCIDENT_FOR_ANALYST = {
    "user_id": 2,
    "title": "New incident assigned",
    "message": "Incident 12 (Phishing attack) was assigned to you.",
    "notification_type": "Incident Assignment",
    "severity": "High",
}
THREAT_FOR_ANALYST = {
    "user_id": 2,
    "title": "Critical threat added",
    "message": "Domain secure-bank-login.example was added as a Critical threat.",
    "notification_type": "Threat Alert",
    "severity": "Critical",
}
SYSTEM_FOR_EMPLOYEE = {
    "user_id": 3,
    "title": "Password policy updated",
    "message": "Passwords must now be changed every 90 days.",
    "notification_type": "System Notification",
    "severity": "Low",
}
SECURITY_FOR_EMPLOYEE = {
    "user_id": 3,
    "title": "Suspicious login detected",
    "message": "A login to your account was blocked from an unknown device.",
    "notification_type": "Security Alert",
    "severity": "Medium",
}
VULNERABILITY_FOR_ADMIN = {
    "user_id": 1,
    "title": "Critical vulnerability found",
    "message": "CVE-2024-3400 affects asset 1 (Main Web Server).",
    "notification_type": "Vulnerability Alert",
    "severity": "Critical",
}
ALL_NOTIFICATIONS = [INCIDENT_FOR_ANALYST, THREAT_FOR_ANALYST, SYSTEM_FOR_EMPLOYEE, SECURITY_FOR_EMPLOYEE,
                     VULNERABILITY_FOR_ADMIN]


@pytest.fixture
def database_path(tmp_path):
    """A brand-new copy of the shared database for every test, so tests never touch the real data."""
    path = init_database("notifications", str(tmp_path / "security_system.db"))
    add_test_users(path)
    return path


@pytest.fixture
def client(database_path):
    """A test client that sends the Security Administrator's token unless a test sends another one."""
    test_client = create_app(database_path).test_client()
    test_client.environ_base["HTTP_AUTHORIZATION"] = "Bearer admin-token"
    return test_client


@pytest.fixture
def stored(client):
    """Create the five sample notifications (IDs 1-5) as the Security Administrator."""
    for notification in ALL_NOTIFICATIONS:
        assert client.post(URL, json=notification).status_code == 201


def ids(response):
    return [n["notification_id"] for n in response.get_json()["data"]]


# ---------- POST /notifications ----------

@pytest.mark.parametrize("notification", ALL_NOTIFICATIONS, ids=lambda n: n["notification_type"])
def test_admin_creates_every_notification_type(client, audit_events, notification):
    response = client.post(URL, json=notification)

    assert response.status_code == 201
    body = response.get_json()
    assert body["message"] == "Notification created successfully"
    for field, value in notification.items():
        assert body["data"][field] == value
    assert body["data"]["status"] == "Unread"
    assert body["data"]["read_at"] is None
    assert body["data"]["created_at"]
    assert audit_events[-1]["action"] == "CREATE_NOTIFICATION"


def test_created_notification_is_stored_in_database(client, database_path):
    client.post(URL, json=INCIDENT_FOR_ANALYST)

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT user_id, notification_type, severity, status, read_at FROM notifications"
        ).fetchone()
    assert row == (2, "Incident Assignment", "High", "Unread", None)


def test_another_service_creates_notification_with_the_service_key(database_path, audit_events):
    service = create_app(database_path).test_client()

    response = service.post(URL, json=THREAT_FOR_ANALYST, headers={"X-Service-Key": config.internal_service_key()})

    assert response.status_code == 201
    assert audit_events[-1]["user_id"] is None
    assert "by an internal service" in audit_events[-1]["description"]


def test_wrong_service_key_is_rejected(database_path):
    service = create_app(database_path).test_client()
    response = service.post(URL, json=THREAT_FOR_ANALYST, headers={"X-Service-Key": "guessed-key"})
    assert response.status_code == 401


def test_user_id_is_a_foreign_key_to_users(database_path):
    with sqlite3.connect(database_path) as connection:
        foreign_keys = connection.execute("PRAGMA foreign_key_list(notifications)").fetchall()

    assert [(key[2], key[3], key[4]) for key in foreign_keys] == [("users", "user_id", "id")]


def test_service_key_with_an_unknown_user_is_stopped_by_the_foreign_key(database_path):
    # Other services are not checked with Service 1, so the database's foreign key catches the bad ID.
    service = create_app(database_path).test_client()

    response = service.post(URL, json={**THREAT_FOR_ANALYST, "user_id": 99},
                            headers={"X-Service-Key": config.internal_service_key()})

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["user_id 99 does not match any registered user"]
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 0


def test_recipient_must_exist_in_users_service(client, database_path):
    response = client.post(URL, json={**INCIDENT_FOR_ANALYST, "user_id": 99})

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["user_id 99 does not match any registered user"]
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 0


def test_recipient_check_needs_users_service(client, monkeypatch):
    def users_down(authorization_header):
        raise users_client.UsersServiceUnavailable()

    monkeypatch.setattr(users_client, "list_users", users_down)
    assert client.post(URL, json=INCIDENT_FOR_ANALYST).status_code == 503


@pytest.mark.parametrize(
    "changes, expected_error",
    [
        ({"notification_type": "Reminder"}, "notification_type must be one of"),
        ({"severity": "Extreme"}, "severity must be one of"),
        ({"severity": "high"}, "severity must be one of"),
        ({"user_id": 0}, "user_id must be a positive whole number"),
        ({"user_id": "2"}, "user_id must be a positive whole number"),
        ({"user_id": True}, "user_id must be a positive whole number"),
        ({"user_id": 99999999999999999999}, "user_id must be a positive whole number"),
        ({"title": "   "}, "title is required"),
        ({"message": 5}, "message must be text"),
        ({"title": "x" * 151}, "title must be at most 150 characters"),
        ({"status": "Read"}, "Unknown field(s): status"),
    ],
)
def test_invalid_input_is_rejected(client, changes, expected_error):
    response = client.post(URL, json={**INCIDENT_FOR_ANALYST, **changes})

    assert response.status_code == 400
    assert any(expected_error in error for error in response.get_json()["errors"])


def test_missing_required_fields_are_all_reported(client):
    response = client.post(URL, json={"title": "Only a title"})

    errors = response.get_json()["errors"]
    for field in ("user_id", "message", "notification_type", "severity"):
        assert f"{field} is required" in errors


@pytest.mark.parametrize("request_options", [{"json": {}}, {"json": []}, {"data": "x", "content_type": "text/plain"}])
def test_empty_or_non_json_body_is_rejected(client, request_options):
    response = client.post(URL, **request_options)
    assert response.get_json()["errors"] == ["Request body must be a non-empty JSON object"]


# ---------- GET /notifications/user/{user_id} ----------

def test_user_notifications_newest_first(client, stored, headers):
    response = client.get(f"{URL}/user/2", headers=headers["analyst"])

    assert response.status_code == 200
    assert response.get_json()["count"] == 2
    assert ids(response) == [2, 1]


def test_user_without_notifications_gets_empty_list(client, stored):
    response = client.get(f"{URL}/user/4")
    assert response.status_code == 200
    assert response.get_json() == {"status": "success", "count": 0, "data": []}


@pytest.mark.parametrize("role, user_id, expected", [
    ("admin", 2, 200), ("auditor", 2, 200),
    ("analyst", 2, 200), ("analyst", 3, 403),
    ("user", 3, 200), ("user", 2, 403),
])
def test_who_can_read_whose_notifications(client, stored, headers, audit_events, role, user_id, expected):
    response = client.get(f"{URL}/user/{user_id}", headers=headers[role])

    assert response.status_code == expected
    if expected == 403:
        assert response.get_json()["message"] == "You may only access your own notifications"
        assert audit_events[-1]["action"] == "PERMISSION_DENIED"


# ---------- GET /notifications/{id} ----------

def test_get_existing_notification(client, stored, headers):
    response = client.get(f"{URL}/3", headers=headers["user"])
    assert response.status_code == 200
    assert response.get_json()["data"]["title"] == "Password policy updated"


def test_get_missing_notification_gets_404(client):
    response = client.get(f"{URL}/999")
    assert response.status_code == 404
    assert response.get_json() == {"status": "error", "message": "Notification with ID 999 not found"}


def test_cannot_read_someone_elses_notification(client, stored, headers):
    assert client.get(f"{URL}/1", headers=headers["user"]).status_code == 403
    assert client.get(f"{URL}/1", headers=headers["analyst2"]).status_code == 403
    assert client.get(f"{URL}/1", headers=headers["auditor"]).status_code == 200


# ---------- PUT /notifications/{id}/read ----------

def test_mark_as_read_records_the_read_date(client, stored, headers, database_path, audit_events):
    response = client.put(f"{URL}/1/read", headers=headers["analyst"])

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert response.get_json()["message"] == "Notification marked as read"
    assert data["status"] == "Read"
    assert data["read_at"]
    with sqlite3.connect(database_path) as connection:
        row = connection.execute("SELECT status, read_at FROM notifications WHERE notification_id = 1").fetchone()
    assert row == ("Read", data["read_at"])
    assert audit_events[-1]["action"] == "MARK_NOTIFICATION_READ"


def test_marking_twice_keeps_the_first_read_date(client, stored, headers, database_path):
    first = client.put(f"{URL}/1/read", headers=headers["analyst"]).get_json()["data"]["read_at"]
    with sqlite3.connect(database_path) as connection:  # pretend the first read was long ago
        connection.execute("UPDATE notifications SET read_at = '2026-01-01 10:00:00' WHERE notification_id = 1")

    second = client.put(f"{URL}/1/read", headers=headers["analyst"])

    assert first
    assert second.status_code == 200
    assert second.get_json()["message"] == "Notification was already marked as read"
    assert second.get_json()["data"]["read_at"] == "2026-01-01 10:00:00"


def test_read_date_is_the_current_utc_time(client, stored):
    read_at = client.put(f"{URL}/1/read").get_json()["data"]["read_at"]

    read_time = datetime.strptime(read_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - read_time).total_seconds()) < 60


def test_repository_never_overwrites_the_first_read_date(database_path):
    repository = NotificationRepository(database_path)
    repository.create(INCIDENT_FOR_ANALYST)
    repository.mark_as_read(1)
    with sqlite3.connect(database_path) as connection:
        connection.execute("UPDATE notifications SET read_at = '2026-01-01 10:00:00' WHERE notification_id = 1")

    assert repository.mark_as_read(1).read_at == "2026-01-01 10:00:00"


@pytest.mark.parametrize("role, notification_id, expected", [
    ("analyst", 1, 200),   # own
    ("analyst", 3, 403),   # the employee's
    ("user", 3, 200),      # own
    ("user", 1, 403),      # the analyst's
    ("admin", 3, 200),     # administrators may mark any
    ("auditor", 3, 403),   # auditors are read-only
])
def test_who_can_mark_as_read(client, stored, headers, role, notification_id, expected):
    assert client.put(f"{URL}/{notification_id}/read", headers=headers[role]).status_code == expected


def test_mark_missing_notification_gets_404(client):
    assert client.put(f"{URL}/999/read").status_code == 404


def test_wrong_method_on_read_route_gets_405(client):
    assert client.post(f"{URL}/1/read").status_code == 405


# ---------- GET /notifications/search ----------

@pytest.mark.parametrize(
    "query, expected_ids",
    [
        ({"user_id": "3"}, [4, 3]),
        ({"notification_type": "Threat Alert"}, [2]),
        ({"severity": "Critical"}, [5, 2]),
        ({"status": "Unread"}, [5, 4, 3, 2, 1]),
        ({"user_id": "2", "severity": "High"}, [1]),
        ({"severity": "Low", "user_id": "1"}, []),
    ],
)
def test_search(client, stored, headers, query, expected_ids):
    response = client.get(f"{URL}/search", query_string=query, headers=headers["auditor"])
    assert response.status_code == 200
    assert ids(response) == expected_ids


def test_search_by_status_read(client, stored):
    client.put(f"{URL}/3/read")
    assert ids(client.get(f"{URL}/search", query_string={"status": "Read"})) == [3]


def test_analyst_search_is_limited_to_own_notifications(client, stored, headers):
    response = client.get(f"{URL}/search", query_string={"severity": "Critical"}, headers=headers["analyst"])
    assert ids(response) == [2]  # notification 5 is also Critical, but belongs to the admin

    other = client.get(f"{URL}/search", query_string={"user_id": "3"}, headers=headers["analyst"])
    assert other.status_code == 403


def test_employee_cannot_search(client, stored, headers):
    assert client.get(f"{URL}/search", query_string={"status": "Unread"}, headers=headers["user"]).status_code == 403


@pytest.mark.parametrize(
    "query, expected_error",
    [
        ({}, "Provide at least one search parameter"),
        ({"type": "Threat Alert"}, "Unknown search parameter(s): type"),
        ({"status": "Seen"}, "status must be one of"),
        ({"severity": "Extreme"}, "severity must be one of"),
        ({"notification_type": "Reminder"}, "notification_type must be one of"),
        ({"user_id": "abc"}, "user_id must be a positive whole number"),
    ],
)
def test_invalid_search_is_rejected(client, query, expected_error):
    response = client.get(f"{URL}/search", query_string=query)
    assert response.status_code == 400
    assert expected_error in response.get_json()["errors"][0]


def test_search_is_safe_from_sql_injection(client, stored, database_path):
    response = client.get(f"{URL}/search", query_string={"status": "Unread' OR '1'='1"})
    assert response.status_code == 400
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM notifications").fetchone()[0] == 5


# ---------- DELETE /notifications/{id} ----------

def test_admin_deletes_notification(client, stored, database_path, audit_events):
    response = client.delete(f"{URL}/2")

    assert response.status_code == 200
    assert response.get_json() == {"status": "success", "message": "Notification 2 deleted successfully"}
    assert client.get(f"{URL}/2").status_code == 404
    assert audit_events[-1]["action"] == "DELETE_NOTIFICATION"
    assert audit_events[-1]["severity"] == "Warning"


@pytest.mark.parametrize("role", ["analyst", "user", "auditor"])
def test_only_admin_can_delete(client, stored, headers, audit_events, role):
    response = client.delete(f"{URL}/1", headers=headers[role])

    assert response.status_code == 403
    assert audit_events[-1]["action"] == "PERMISSION_DENIED"
    assert client.get(f"{URL}/1").status_code == 200


def test_delete_missing_notification_gets_404(client):
    assert client.delete(f"{URL}/999").status_code == 404


# ---------- Authentication and routes ----------

ENDPOINTS = [
    ("POST", URL), ("GET", f"{URL}/user/2"), ("GET", f"{URL}/1"), ("PUT", f"{URL}/1/read"),
    ("GET", f"{URL}/search?status=Unread"), ("DELETE", f"{URL}/1"),
]


@pytest.mark.parametrize("method, url", ENDPOINTS)
def test_request_without_token_gets_401(database_path, audit_events, method, url):
    response = create_app(database_path).test_client().open(url, method=method, json={})
    assert response.status_code == 401
    assert audit_events[-1]["action"] == "UNAUTHENTICATED_ACCESS"


# Expected status code for every (endpoint, role) pair when the user is allowed to see the record.
PERMISSION_MATRIX = {
    ("POST", URL): {"admin": 201, "analyst": 403, "auditor": 403, "user": 403},
    ("GET", f"{URL}/user/2"): {"admin": 200, "analyst": 200, "auditor": 200, "user": 403},
    ("GET", f"{URL}/1"): {"admin": 200, "analyst": 200, "auditor": 200, "user": 403},
    ("PUT", f"{URL}/1/read"): {"admin": 200, "analyst": 200, "auditor": 403, "user": 403},
    ("GET", f"{URL}/search?status=Unread"): {"admin": 200, "analyst": 200, "auditor": 200, "user": 403},
    ("DELETE", f"{URL}/1"): {"admin": 200, "analyst": 403, "auditor": 403, "user": 403},
}


@pytest.mark.parametrize(
    "method, url, role, expected_status",
    [(m, u, role, status) for (m, u), roles in PERMISSION_MATRIX.items() for role, status in roles.items()],
)
def test_role_permissions(client, stored, headers, method, url, role, expected_status):
    body = SYSTEM_FOR_EMPLOYEE if method == "POST" else None
    assert client.open(url, method=method, json=body, headers=headers[role]).status_code == expected_status


def test_route_without_student_name_does_not_exist(client):
    assert client.get("/notifications/user/1").status_code == 404


@pytest.mark.parametrize("url", [f"{URL}/99999999999999999999", f"{URL}/user/99999999999999999999"])
def test_huge_ids_get_404_or_empty_not_a_crash(client, url):
    assert client.get(url).status_code in (200, 404)


def test_database_rejects_read_status_without_read_date(database_path):
    with sqlite3.connect(database_path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO notifications (user_id, title, message, notification_type, severity, status) "
            "VALUES (1, 't', 'm', 'Security Alert', 'Low', 'Read')"
        )
