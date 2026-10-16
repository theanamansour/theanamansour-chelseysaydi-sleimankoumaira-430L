"""
Test helpers shared by all of Sleiman Koumaira's service tests.

The automated tests must not depend on other services running, so Service 1 (login and users)
and Service 8 (notifications) are replaced by small in-memory stand-ins here. These stand-ins
exist only inside the tests; the running services always call the real ones.
"""
import os

import pytest

from database.connection import get_db
from shared import audit_client, auth, notification_client, users_client
from shared.auth import ADMIN, ANALYST, AUDITOR, REGULAR_EMPLOYEE

# Token -> user, as Service 1's verify endpoint would answer.
TEST_TOKENS = {
    "admin-token": {"user_id": 1, "username": "test_admin", "role": ADMIN},
    "analyst-token": {"user_id": 2, "username": "test_analyst", "role": ANALYST},
    "employee-token": {"user_id": 3, "username": "test_employee", "role": REGULAR_EMPLOYEE},
    "auditor-token": {"user_id": 4, "username": "test_auditor", "role": AUDITOR},
    "analyst2-token": {"user_id": 5, "username": "test_analyst_2", "role": ANALYST},
}

# What GET /theana-mansour/users returns in the tests.
TEST_USERS = [
    {"id": 1, "username": "test_admin", "role": ADMIN, "account_status": "Active"},
    {"id": 2, "username": "test_analyst", "role": ANALYST, "account_status": "Active"},
    {"id": 3, "username": "test_employee", "role": REGULAR_EMPLOYEE, "account_status": "Active"},
    {"id": 4, "username": "test_auditor", "role": AUDITOR, "account_status": "Active"},
    {"id": 5, "username": "test_analyst_2", "role": ANALYST, "account_status": "Active"},
    {"id": 6, "username": "suspended_analyst", "role": ANALYST, "account_status": "Suspended"},
]


def add_test_users(database_path):
    """
    The shared database checks owner_id and user_id with real foreign keys, so a test database
    needs the same users as the fake Service 1 above.
    """
    with get_db(database_path) as connection:
        connection.executemany(
            "INSERT INTO users (id, full_name, username, email, password_hash, department, role, account_status)"
            " VALUES (?, ?, ?, ?, 'not-used-in-tests', 'Security', ?, ?)",
            [
                (user["id"], user["username"], user["username"], f"{user['username']}@example.com",
                 user["role"], user["account_status"])
                for user in TEST_USERS
            ],
        )


@pytest.fixture(autouse=True)
def test_internal_service_key(monkeypatch):
    """Use a made-up internal key, so the tests never create the real .internal_service_key file."""
    if not os.environ.get("INTERNAL_SERVICE_KEY"):
        monkeypatch.setenv("INTERNAL_SERVICE_KEY", "test-internal-service-key")


@pytest.fixture(autouse=True)
def fake_users_service(monkeypatch):
    """Stand-in for Service 1's verify endpoint and user list."""

    def fake_verify_token(authorization_header):
        token = authorization_header.partition(" ")[2].strip()
        if token == "expired-token":
            return None, "Token expired"
        if token in TEST_TOKENS:
            return dict(TEST_TOKENS[token]), None
        return None, "Invalid token"

    monkeypatch.setattr(auth, "verify_token", fake_verify_token)
    monkeypatch.setattr(users_client, "list_users", lambda authorization_header: [dict(u) for u in TEST_USERS])


@pytest.fixture(autouse=True)
def sent_notifications(monkeypatch):
    """Capture notifications that a service would send to Service 8."""
    notifications = []

    def fake_send_notification(**notification):
        notifications.append(notification)
        return True

    monkeypatch.setattr(notification_client, "send_notification", fake_send_notification)
    return notifications


@pytest.fixture(autouse=True)
def audit_events(monkeypatch):
    """Capture audit logs in a list instead of sending them to Service 5."""
    events = []
    monkeypatch.setattr(audit_client, "send_audit_log", lambda **log_record: events.append(log_record))
    return events


@pytest.fixture
def headers():
    """Authorization headers for one test user of each role."""
    return {
        "admin": {"Authorization": "Bearer admin-token"},
        "analyst": {"Authorization": "Bearer analyst-token"},
        "user": {"Authorization": "Bearer employee-token"},
        "auditor": {"Authorization": "Bearer auditor-token"},
        "analyst2": {"Authorization": "Bearer analyst2-token"},
    }
