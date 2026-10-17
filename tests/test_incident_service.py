import sqlite3

import pytest

from services.incidents import integrations
from services.incidents.app import ROUTE_PREFIX, create_app
from services.incidents.auth import ADMIN, ANALYST, AUDITOR, EMPLOYEE

URL = f"{ROUTE_PREFIX}/incidents"
INCIDENT = {
    "title": "Phishing email opened",
    "description": "An employee opened a suspicious attachment.",
    "category": "Phishing",
    "severity": "High",
    "reporter_id": 3,
    "asset_id": 8,
}
USERS = {
    1: {"id": 1, "username": "admin", "role": ADMIN},
    2: {"id": 2, "username": "analyst", "role": ANALYST},
    3: {"id": 3, "username": "employee", "role": EMPLOYEE},
    4: {"id": 4, "username": "auditor", "role": AUDITOR},
    5: {"id": 5, "username": "other_analyst", "role": ANALYST},
}


@pytest.fixture
def database_path(tmp_path, seed_database):
    path = tmp_path / "security_system.db"
    seed_database(path, asset_ids=(8,))
    return path


@pytest.fixture
def audit_events(monkeypatch):
    events = []
    monkeypatch.setattr(
        integrations, "send_audit_log", lambda *args: events.append(args)
    )
    return events


@pytest.fixture
def client(database_path, monkeypatch, audit_events):
    tokens = {
        f"Bearer {user['username']}": {
            "valid": True,
            "user_id": user_id,
            "username": user["username"],
            "role": user["role"],
        }
        for user_id, user in USERS.items()
    }
    monkeypatch.setattr(
        integrations,
        "verify_identity",
        lambda authorization: (
            (tokens[authorization], None)
            if authorization in tokens
            else (None, "Invalid token")
        ),
    )
    monkeypatch.setattr(
        integrations,
        "get_user",
        lambda user_id, _authorization: USERS.get(user_id),
    )
    return create_app(database_path).test_client()


def auth(username):
    return {"Authorization": f"Bearer {username}"}


def create_incident(client, headers=None, data=None):
    return client.post(
        URL, json=data or INCIDENT, headers=headers or auth("employee")
    )


def assign_incident(client, analyst_id=2):
    return client.put(
        f"{URL}/1/assign",
        json={"analyst_id": analyst_id},
        headers=auth("admin"),
    )


def test_create_incident_and_store_it(client, database_path, audit_events):
    response = create_incident(client)

    assert response.status_code == 201
    body = response.get_json()
    assert body["message"] == "Incident created successfully"
    assert body["data"]["status"] == "Open"
    assert body["data"]["investigation_notes"] == []
    with sqlite3.connect(database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
    assert audit_events[-1][1] == "INCIDENT_CREATED"


@pytest.mark.parametrize("severity", ["Low", "Medium", "High", "Critical"])
def test_all_severity_levels_are_supported(client, severity):
    response = create_incident(client, data={**INCIDENT, "severity": severity})
    assert response.status_code == 201
    assert response.get_json()["data"]["severity"] == severity


@pytest.mark.parametrize(
    "changes, error_text",
    [
        ({"title": ""}, "title is required"),
        ({"description": None}, "description is required"),
        ({"category": 10}, "category is required"),
        ({"severity": "Emergency"}, "severity must be one of"),
        ({"reporter_id": True}, "reporter_id must be a positive whole number"),
        ({"asset_id": 0}, "asset_id must be a positive whole number"),
        ({"unexpected": "value"}, "Unknown field(s): unexpected"),
    ],
)
def test_invalid_incident_is_rejected(client, changes, error_text):
    response = create_incident(client, data={**INCIDENT, **changes})
    assert response.status_code == 400
    assert any(error_text in item for item in response.get_json()["errors"])


def test_missing_asset_is_rejected(client):
    response = create_incident(client, data={**INCIDENT, "asset_id": 999})
    assert response.status_code == 400
    assert response.get_json()["message"] == "Affected asset not found"


def test_employee_report_checks_asset_in_shared_database(client, monkeypatch):
    def asset_service_must_not_be_called(*_args, **_kwargs):
        raise AssertionError("Service 2 should not be called to check the asset")

    monkeypatch.setattr(integrations.requests, "get", asset_service_must_not_be_called)

    assert create_incident(client).status_code == 201
    response = create_incident(client, data={**INCIDENT, "asset_id": 9})
    assert response.status_code == 400
    assert response.get_json()["message"] == "Affected asset not found"


def test_foreign_keys_are_enforced_by_the_database(database_path):
    create_app(database_path)
    with sqlite3.connect(database_path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute("PRAGMA foreign_keys = ON")
        db.execute(
            """
            INSERT INTO incidents
                (title, description, category, severity, reporter_id, asset_id)
            VALUES ('Test', 'Unknown reporter', 'Test', 'Low', 999, 8)
            """
        )


def test_employee_cannot_report_as_someone_else(client):
    response = create_incident(client, data={**INCIDENT, "reporter_id": 1})
    assert response.status_code == 403


def test_admin_cannot_use_unknown_reporter(client):
    response = create_incident(
        client, headers=auth("admin"), data={**INCIDENT, "reporter_id": 999}
    )
    assert response.status_code == 400
    assert response.get_json()["message"] == "Reporter user not found"


def test_retrieve_all_is_admin_and_auditor_only(client):
    create_incident(client)

    assert client.get(URL, headers=auth("admin")).get_json()["count"] == 1
    assert client.get(URL, headers=auth("auditor")).status_code == 200
    assert client.get(URL, headers=auth("employee")).status_code == 403
    assert client.get(URL, headers=auth("analyst")).status_code == 403


def test_retrieve_specific_enforces_relationships(client):
    create_incident(client)

    assert client.get(f"{URL}/1", headers=auth("employee")).status_code == 200
    assert client.get(f"{URL}/1", headers=auth("analyst")).status_code == 403
    assign_incident(client)
    assert client.get(f"{URL}/1", headers=auth("analyst")).status_code == 200
    assert client.get(f"{URL}/1", headers=auth("other_analyst")).status_code == 403
    assert client.get(f"{URL}/999", headers=auth("admin")).status_code == 404


def test_only_admin_can_assign_security_analyst(client, audit_events):
    create_incident(client)

    assert assign_incident(client).status_code == 200
    assert client.get(
        f"{URL}/1", headers=auth("admin")
    ).get_json()["data"]["assigned_analyst_id"] == 2
    assert assign_incident(client, analyst_id=3).status_code == 400
    assert client.put(
        f"{URL}/1/assign",
        json={"analyst_id": 2},
        headers=auth("analyst"),
    ).status_code == 403
    assert any(event[1] == "INCIDENT_ASSIGNED" for event in audit_events)


def test_assignment_notifies_the_analyst(client, sent_notifications):
    create_incident(client)
    assign_incident(client, analyst_id=3)
    assert sent_notifications == []

    assert assign_incident(client).status_code == 200
    assert sent_notifications == [
        {
            "user_id": 2,
            "title": "Incident assigned",
            "message": "Incident 1: Phishing email opened has been assigned to you.",
            "notification_type": "Incident Assignment",
            "severity": "High",
        }
    ]


def test_complete_status_lifecycle_sets_resolution_date(client):
    create_incident(client)
    assign_incident(client)

    for status in ("Under Investigation", "Mitigated", "Resolved", "Closed"):
        response = client.put(
            f"{URL}/1/status",
            json={"status": status},
            headers=auth("analyst"),
        )
        assert response.status_code == 200
        assert response.get_json()["data"]["status"] == status

    assert response.get_json()["data"]["resolution_date"] is not None


def test_invalid_status_transition_is_rejected(client):
    create_incident(client)
    assign_incident(client)

    response = client.put(
        f"{URL}/1/status",
        json={"status": "Closed"},
        headers=auth("analyst"),
    )
    assert response.status_code == 400
    assert "Open can only move to Under Investigation" in response.get_json()[
        "errors"
    ][0]


def test_unassigned_analyst_cannot_modify_incident(client):
    create_incident(client)

    status_response = client.put(
        f"{URL}/1/status",
        json={"status": "Under Investigation"},
        headers=auth("analyst"),
    )
    note_response = client.post(
        f"{URL}/1/notes",
        json={"note_content": "Checked email headers."},
        headers=auth("analyst"),
    )
    assert status_response.status_code == 403
    assert note_response.status_code == 403


def test_add_note_and_return_it_with_incident(client, database_path):
    create_incident(client)
    assign_incident(client)

    response = client.post(
        f"{URL}/1/notes",
        json={"note_content": "  Attachment hash collected.  "},
        headers=auth("analyst"),
    )
    assert response.status_code == 201
    assert response.get_json()["data"]["analyst_id"] == 2
    assert response.get_json()["data"]["note_content"] == "Attachment hash collected."

    incident = client.get(f"{URL}/1", headers=auth("analyst")).get_json()["data"]
    assert len(incident["investigation_notes"]) == 1
    with sqlite3.connect(database_path) as db:
        assert db.execute(
            "SELECT incident_id FROM investigation_notes"
        ).fetchone()[0] == 1


def test_authentication_and_role_errors(client, audit_events):
    assert client.get(URL).status_code == 401
    assert client.get(URL, headers={"Authorization": "Bearer bad"}).status_code == 401
    assert client.get(URL, headers=auth("employee")).status_code == 403
    assert any(event[1] == "PERMISSION_DENIED" for event in audit_events)


def test_student_name_is_in_every_route(client):
    assert ROUTE_PREFIX == "/chelsea-saydi"
    assert client.get("/incidents", headers=auth("admin")).status_code == 404


def test_database_constraints_reject_invalid_values(database_path):
    create_app(database_path)
    with sqlite3.connect(database_path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute(
            """
            INSERT INTO incidents
                (title, description, category, severity, reporter_id, asset_id)
            VALUES ('Bad', 'Bad severity', 'Test', 'Extreme', 1, 1)
            """
        )
