"""Test helpers shared by all of Sleiman Koumaira's service tests."""
import pytest

from database.init_db import init_database
from shared import audit_client
from shared.auth import ADMIN, ANALYST, AUDITOR, REGULAR_EMPLOYEE, create_access_token


@pytest.fixture
def database_path(tmp_path):
    """A brand-new database file for every test, so tests never touch the real data."""
    path = str(tmp_path / "test.db")
    init_database(path)
    return path


@pytest.fixture
def audit_events(monkeypatch):
    """Capture audit logs in a list instead of sending them to Service 5."""
    events = []
    monkeypatch.setattr(audit_client, "send_audit_log", lambda **log_record: events.append(log_record))
    return events


@pytest.fixture
def headers():
    """Authorization headers for one test user of each role."""

    def bearer(user_id, username, role):
        return {"Authorization": f"Bearer {create_access_token(user_id, username, role)}"}

    return {
        "admin": bearer(1, "test_admin", ADMIN),
        "analyst": bearer(2, "test_analyst", ANALYST),
        "user": bearer(3, "test_employee", REGULAR_EMPLOYEE),
        "auditor": bearer(4, "test_auditor", AUDITOR),
    }
