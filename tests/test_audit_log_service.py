import sqlite3

import pytest

from services.audit_logs import auth as auth_module
from services.audit_logs.app import ROUTE_PREFIX, create_app
from services.audit_logs.auth import ADMIN, ANALYST, AUDITOR, EMPLOYEE

URL = f"{ROUTE_PREFIX}/logs"
SERVICE_KEY = "test-internal-key"
LOG = {
    "user_id": 3,
    "action": "INCIDENT_CREATED",
    "description": "Incident 12 was reported",
    "severity": "Information",
    "related_service": "Incident Management Service",
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
def database_path(tmp_path):
    return tmp_path / "audit.db"


@pytest.fixture
def client(database_path, monkeypatch):
    def verify(authorization):
        token = authorization.removeprefix("Bearer ")
        identity = IDENTITIES.get(token)
        if identity is None:
            return None, auth_module.error("Invalid token", 401)
        return identity, None

    monkeypatch.setattr(auth_module, "verify_identity", verify)
    return create_app(database_path, SERVICE_KEY).test_client()


def auth(role):
    return {"Authorization": f"Bearer {role}"}


def internal_headers():
    return {"X-Service-Key": SERVICE_KEY}


def create_log(client, data=None, headers=None):
    return client.post(
        URL,
        json=data or LOG,
        headers=headers or internal_headers(),
    )


def test_internal_service_can_create_log(client, database_path):
    response = create_log(client)

    assert response.status_code == 201
    body = response.get_json()
    assert body["message"] == "Security log created successfully"
    assert body["data"]["log_id"] == 1
    assert body["data"]["action"] == "INCIDENT_CREATED"
    assert body["data"]["timestamp"]
    with sqlite3.connect(database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == 1


def test_administrator_can_create_log_without_service_key(client):
    response = create_log(client, headers=auth("admin"))
    assert response.status_code == 201


@pytest.mark.parametrize(
    "severity", ["Information", "Warning", "Error", "Critical"]
)
def test_all_severity_levels_are_supported(client, severity):
    response = create_log(client, data={**LOG, "severity": severity})
    assert response.status_code == 201
    assert response.get_json()["data"]["severity"] == severity


@pytest.mark.parametrize(
    "changes, expected",
    [
        ({"user_id": 0}, "user_id must be a positive whole number"),
        ({"user_id": True}, "user_id must be a positive whole number"),
        ({"action": ""}, "action is required"),
        ({"description": None}, "description is required"),
        ({"severity": "Low"}, "severity must be one of"),
        ({"related_service": 5}, "related_service is required"),
        ({"extra": "no"}, "Unknown field(s): extra"),
    ],
)
def test_invalid_logs_are_rejected(client, changes, expected):
    response = create_log(client, data={**LOG, **changes})
    assert response.status_code == 400
    assert any(expected in item for item in response.get_json()["errors"])


def test_unknown_user_is_allowed_for_failed_authentication_events(client):
    response = create_log(
        client,
        data={
            **LOG,
            "user_id": None,
            "action": "FAILED_LOGIN",
            "severity": "Warning",
        },
    )
    assert response.status_code == 201
    assert response.get_json()["data"]["user_id"] is None


def test_retrieve_all_is_admin_and_auditor_only(client):
    create_log(client)
    create_log(client, data={**LOG, "action": "LOGIN_SUCCESS"})

    assert client.get(URL, headers=auth("admin")).get_json()["count"] == 2
    assert client.get(URL, headers=auth("auditor")).status_code == 200
    assert client.get(URL, headers=auth("analyst")).status_code == 403
    assert client.get(URL, headers=auth("employee")).status_code == 403


def test_retrieve_specific_log(client):
    create_log(client)

    response = client.get(f"{URL}/1", headers=auth("analyst"))
    assert response.status_code == 200
    assert response.get_json()["data"]["description"] == LOG["description"]
    assert client.get(f"{URL}/999", headers=auth("admin")).status_code == 404


def test_search_supports_every_required_filter(client):
    first = create_log(client).get_json()["data"]
    create_log(
        client,
        data={
            "user_id": 2,
            "action": "FAILED_LOGIN",
            "description": "Incorrect password",
            "severity": "Warning",
            "related_service": "Users and Identity Management Service",
        },
    )
    day = first["timestamp"][:10]

    searches = (
        ({"user_id": "3"}, 1),
        ({"date": day}, 2),
        ({"action": "incident"}, 1),
        ({"severity": "Warning"}, 1),
        ({"related_service": "identity"}, 1),
        ({"user_id": "2", "severity": "Warning"}, 1),
        ({"action": "does-not-exist"}, 0),
    )
    for query, count in searches:
        response = client.get(
            f"{URL}/search", query_string=query, headers=auth("analyst")
        )
        assert response.status_code == 200
        assert response.get_json()["count"] == count


@pytest.mark.parametrize(
    "query, expected",
    [
        ({}, "Provide at least one search parameter"),
        ({"unknown": "x"}, "Unknown search parameter"),
        ({"user_id": "abc"}, "user_id must be a positive whole number"),
        ({"date": "14/10/2026"}, "date must use YYYY-MM-DD"),
        ({"severity": "Low"}, "severity must be one of"),
    ],
)
def test_invalid_search_is_rejected(client, query, expected):
    response = client.get(
        f"{URL}/search", query_string=query, headers=auth("admin")
    )
    assert response.status_code == 400
    assert expected in response.get_json()["errors"][0]


def test_search_escapes_sql_and_wildcards(client, database_path):
    create_log(client)

    injection = client.get(
        f"{URL}/search",
        query_string={"action": "' OR '1'='1"},
        headers=auth("admin"),
    )
    wildcard = client.get(
        f"{URL}/search",
        query_string={"action": "%"},
        headers=auth("admin"),
    )
    assert injection.get_json()["count"] == 0
    assert wildcard.get_json()["count"] == 0
    with sqlite3.connect(database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == 1


def test_retrieve_logs_by_user_and_empty_result(client):
    create_log(client)

    response = client.get(f"{URL}/user/3", headers=auth("auditor"))
    empty = client.get(f"{URL}/user/999", headers=auth("auditor"))
    assert response.get_json()["count"] == 1
    assert empty.get_json() == {"status": "success", "count": 0, "data": []}
    assert client.get(f"{URL}/user/3", headers=auth("analyst")).status_code == 403


def test_only_admin_can_delete_and_deletion_is_logged(client):
    create_log(client)

    assert client.delete(f"{URL}/1", headers=auth("auditor")).status_code == 403
    response = client.delete(f"{URL}/1", headers=auth("admin"))
    assert response.status_code == 200

    logs = client.get(URL, headers=auth("admin")).get_json()["data"]
    assert all(log["log_id"] != 1 for log in logs)
    assert any(log["action"] == "AUDIT_LOG_DELETED" for log in logs)


def test_database_prevents_log_modification(client, database_path):
    create_log(client)

    with sqlite3.connect(database_path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "UPDATE audit_logs SET description = 'changed' WHERE log_id = 1"
        )


def test_unauthorized_attempts_are_automatically_recorded(client, database_path):
    assert client.get(URL).status_code == 401
    assert client.get(URL, headers=auth("employee")).status_code == 403

    with sqlite3.connect(database_path) as db:
        actions = [
            row[0]
            for row in db.execute(
                "SELECT action FROM audit_logs ORDER BY log_id"
            ).fetchall()
        ]
    assert actions == ["UNAUTHENTICATED_ACCESS", "PERMISSION_DENIED"]


def test_wrong_internal_key_does_not_bypass_authentication(client):
    response = create_log(client, headers={"X-Service-Key": "wrong"})
    assert response.status_code == 401


def test_route_contains_student_full_name(client):
    assert ROUTE_PREFIX == "/chelsea-saydi"
    assert client.get("/logs", headers=auth("admin")).status_code == 404
