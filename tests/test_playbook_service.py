import sqlite3

import pytest

from services.playbooks import auth as auth_module
from services.playbooks.app import ROUTE_PREFIX, create_app
from services.playbooks.auth import ADMIN, ANALYST, AUDITOR, EMPLOYEE

URL = f"{ROUTE_PREFIX}/playbooks"
PLAYBOOK = {
    "playbook_name": "Phishing Response",
    "description": "Standard response procedure for reported phishing emails.",
    "incident_category": "Phishing",
    "severity": "High",
}
IDENTITIES = {
    "admin": {"valid": True, "user_id": 1, "username": "admin", "role": ADMIN},
    "analyst": {
        "valid": True,
        "user_id": 2,
        "username": "analyst",
        "role": ANALYST,
    },
    "employee": {
        "valid": True,
        "user_id": 3,
        "username": "employee",
        "role": EMPLOYEE,
    },
    "auditor": {
        "valid": True,
        "user_id": 4,
        "username": "auditor",
        "role": AUDITOR,
    },
}


@pytest.fixture
def database_path(tmp_path, seed_database):
    path = tmp_path / "security_system.db"
    seed_database(path)
    return path


@pytest.fixture
def audit_events(monkeypatch):
    events = []
    monkeypatch.setattr(
        auth_module, "send_audit_log", lambda *args: events.append(args)
    )
    monkeypatch.setattr(
        "services.playbooks.app.send_audit_log",
        lambda *args: events.append(args),
    )
    return events


@pytest.fixture
def client(database_path, monkeypatch, audit_events):
    def verify(authorization):
        token = authorization.removeprefix("Bearer ")
        identity = IDENTITIES.get(token)
        if identity is None:
            return None, auth_module.error("Invalid token", 401)
        return identity, None

    monkeypatch.setattr(auth_module, "verify_identity", verify)
    return create_app(database_path).test_client()


def auth(role):
    return {"Authorization": f"Bearer {role}"}


def create_playbook(client, data=None):
    return client.post(URL, json=data or PLAYBOOK, headers=auth("admin"))


def add_action(client, step, description=None, role="analyst"):
    return client.post(
        f"{URL}/1/actions",
        json={
            "action_description": description or f"Response step {step}",
            "step_number": step,
        },
        headers=auth(role),
    )


def update_action(client, action_id, status, assigned_user_id=None):
    body = {"status": status}
    if assigned_user_id is not None:
        body["assigned_user_id"] = assigned_user_id
    return client.put(
        f"{ROUTE_PREFIX}/actions/{action_id}/status",
        json=body,
        headers=auth("analyst"),
    )


def test_admin_can_create_playbook(client, database_path, audit_events):
    response = create_playbook(client)

    assert response.status_code == 201
    playbook = response.get_json()["data"]
    assert playbook["playbook_id"] == 1
    assert playbook["created_by"] == 1
    assert playbook["actions"] == []
    with sqlite3.connect(database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0] == 1
    assert audit_events[-1][1] == "PLAYBOOK_CREATED"


@pytest.mark.parametrize("severity", ["Low", "Medium", "High", "Critical"])
def test_all_severity_levels_are_supported(client, severity):
    response = create_playbook(client, {**PLAYBOOK, "severity": severity})
    assert response.status_code == 201


@pytest.mark.parametrize(
    "changes, expected",
    [
        ({"playbook_name": ""}, "playbook_name is required"),
        ({"description": None}, "description is required"),
        ({"incident_category": 5}, "incident_category is required"),
        ({"severity": "Emergency"}, "severity must be one of"),
        ({"created_by": 1}, "Unknown field(s): created_by"),
    ],
)
def test_invalid_playbook_is_rejected(client, changes, expected):
    response = create_playbook(client, {**PLAYBOOK, **changes})
    assert response.status_code == 400
    assert any(expected in item for item in response.get_json()["errors"])


def test_duplicate_playbook_name_is_rejected(client):
    create_playbook(client)

    response = create_playbook(client)
    assert response.status_code == 409
    assert "already exists" in response.get_json()["message"]


def test_assigning_unknown_user_is_rejected_without_changing_action(client):
    create_playbook(client)
    add_action(client, 1)

    response = update_action(client, 1, "In Progress", assigned_user_id=999)
    assert response.status_code == 400
    assert response.get_json()["message"] == "User with ID 999 not found"

    action = client.get(f"{URL}/1", headers=auth("admin")).get_json()["data"][
        "actions"
    ][0]
    assert action["status"] == "Pending"
    assert len(action["history"]) == 1


def test_only_admin_can_create_and_employee_has_no_access(client):
    assert client.post(URL, json=PLAYBOOK, headers=auth("analyst")).status_code == 403
    assert client.get(URL, headers=auth("employee")).status_code == 403


def test_admin_analyst_and_auditor_can_retrieve_playbooks(client):
    create_playbook(client)

    for role in ("admin", "analyst", "auditor"):
        response = client.get(URL, headers=auth(role))
        assert response.status_code == 200
        assert response.get_json()["count"] == 1


def test_retrieve_specific_playbook_and_missing_id(client):
    create_playbook(client)

    response = client.get(f"{URL}/1", headers=auth("auditor"))
    assert response.status_code == 200
    assert response.get_json()["data"]["playbook_name"] == "Phishing Response"
    assert client.get(f"{URL}/999", headers=auth("admin")).status_code == 404


def test_admin_and_analyst_can_add_ordered_actions(client, database_path):
    create_playbook(client)

    first = add_action(client, 1, "Collect the suspicious email", "admin")
    second = add_action(client, 2, "Isolate affected workstation", "analyst")
    assert first.status_code == 201
    assert second.status_code == 201

    playbook = client.get(f"{URL}/1", headers=auth("analyst")).get_json()["data"]
    assert [action["step_number"] for action in playbook["actions"]] == [1, 2]
    assert all(action["status"] == "Pending" for action in playbook["actions"])
    with sqlite3.connect(database_path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM response_action_history"
        ).fetchone()[0] == 2


@pytest.mark.parametrize(
    "body, expected",
    [
        ({"action_description": "", "step_number": 1}, "action_description is required"),
        ({"action_description": "Test", "step_number": 0}, "step_number must be a positive"),
        ({"action_description": "Test", "step_number": True}, "step_number must be a positive"),
        ({"action_description": "Test", "step_number": 1, "x": 2}, "Unknown field(s): x"),
    ],
)
def test_invalid_action_is_rejected(client, body, expected):
    create_playbook(client)
    response = client.post(f"{URL}/1/actions", json=body, headers=auth("admin"))
    assert response.status_code == 400
    assert expected in response.get_json()["errors"][0]


def test_duplicate_step_number_is_rejected(client):
    create_playbook(client)
    add_action(client, 1)

    response = add_action(client, 1, "Duplicate")
    assert response.status_code == 409
    assert "already exists" in response.get_json()["message"]


def test_add_action_to_missing_playbook_returns_404(client):
    response = client.post(
        f"{URL}/999/actions",
        json={"action_description": "Test", "step_number": 1},
        headers=auth("analyst"),
    )
    assert response.status_code == 404


def test_complete_action_lifecycle_and_assignment(client, audit_events):
    create_playbook(client)
    add_action(client, 1)

    started = update_action(client, 1, "In Progress", assigned_user_id=2)
    completed = update_action(client, 1, "Completed")
    assert started.status_code == 200
    assert started.get_json()["data"]["assigned_user_id"] == 2
    assert completed.status_code == 200
    assert completed.get_json()["data"]["completion_date"] is not None
    history = completed.get_json()["data"]["history"]
    assert [entry["new_status"] for entry in history] == [
        "Pending",
        "In Progress",
        "Completed",
    ]
    assert audit_events[-1][1] == "RESPONSE_ACTION_UPDATED"


def test_action_order_is_enforced(client):
    create_playbook(client)
    add_action(client, 1)
    add_action(client, 2)

    blocked = update_action(client, 2, "In Progress")
    assert blocked.status_code == 409
    assert "Earlier response actions must be completed" in blocked.get_json()[
        "message"
    ]

    update_action(client, 1, "In Progress")
    update_action(client, 1, "Completed")
    assert update_action(client, 2, "In Progress").status_code == 200


def test_invalid_status_transitions_are_rejected(client):
    create_playbook(client)
    add_action(client, 1)

    skipped = update_action(client, 1, "Completed")
    assert skipped.status_code == 400
    assert "Pending can only move to In Progress" in skipped.get_json()["errors"][0]

    update_action(client, 1, "In Progress")
    update_action(client, 1, "Completed")
    closed = update_action(client, 1, "In Progress")
    assert closed.status_code == 400
    assert "Completed actions cannot change status" in closed.get_json()["errors"][0]


@pytest.mark.parametrize(
    "body, expected",
    [
        ({}, "Request body must be a non-empty JSON object"),
        ({"assigned_user_id": 2}, "status is required"),
        ({"status": "Started"}, "status must be one of"),
        ({"status": "In Progress", "assigned_user_id": 0}, "assigned_user_id must be"),
        ({"status": "In Progress", "completion_date": "now"}, "Unknown field(s)"),
    ],
)
def test_invalid_action_update_is_rejected(client, body, expected):
    create_playbook(client)
    add_action(client, 1)
    response = client.put(
        f"{ROUTE_PREFIX}/actions/1/status",
        json=body,
        headers=auth("analyst"),
    )
    assert response.status_code == 400
    assert expected in response.get_json()["errors"][0]


def test_only_admin_can_delete_and_cascade_actions(client, database_path):
    create_playbook(client)
    add_action(client, 1)

    assert client.delete(f"{URL}/1", headers=auth("analyst")).status_code == 403
    assert client.delete(f"{URL}/1", headers=auth("admin")).status_code == 200
    with sqlite3.connect(database_path) as db:
        assert db.execute("PRAGMA foreign_keys = ON") is not None
        assert db.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM response_action_history"
        ).fetchone()[0] == 0


def test_authentication_errors(client, audit_events):
    assert client.get(URL).status_code == 401
    assert client.get(URL, headers={"Authorization": "Bearer bad"}).status_code == 401
    assert client.get(URL, headers=auth("employee")).status_code == 403
    assert any(event[1] == "PERMISSION_DENIED" for event in audit_events)


def test_database_constraints_reject_invalid_status(database_path):
    create_app(database_path)
    with sqlite3.connect(database_path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute(
            """
            INSERT INTO playbooks
                (playbook_name, description, incident_category, severity, created_by)
            VALUES ('Test', 'Test', 'Test', 'Emergency', 1)
            """
        )


def test_route_contains_student_full_name(client):
    assert ROUTE_PREFIX == "/chelsea-saydi"
    assert client.get("/playbooks", headers=auth("admin")).status_code == 404
