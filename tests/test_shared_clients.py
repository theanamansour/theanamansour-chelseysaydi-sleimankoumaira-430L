"""
Tests for the shared code that talks to other services (Sleiman Koumaira).

The HTTP library is replaced by small fakes so that every answer Service 1, Service 5 or
Service 8 could give (success, rejection, no answer) is checked without running them.
"""
import pytest
import requests
from flask import Flask

from shared import audit_client, auth, config, notification_client, users_client


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def raise_connection_error(*args, **kwargs):
    raise requests.ConnectionError("service is down")


# The autouse stand-ins in conftest.py replace these functions; these tests need the real ones.
REAL_VERIFY_TOKEN = auth.verify_token
REAL_LIST_USERS = users_client.list_users
REAL_SEND_NOTIFICATION = notification_client.send_notification
REAL_SEND_AUDIT_LOG = audit_client.send_audit_log


# ---------- auth.verify_token -> Service 1 POST /theana-mansour/auth/verify ----------

def test_verify_token_returns_user_when_service1_accepts(monkeypatch):
    calls = []

    def fake_post(url, headers, timeout):
        calls.append((url, headers))
        return FakeResponse(200, {"valid": True, "user_id": 7, "username": "sara", "role": "Auditor"})

    monkeypatch.setattr(auth.requests, "post", fake_post)
    user, problem = REAL_VERIFY_TOKEN("Bearer abc")

    assert user == {"user_id": 7, "username": "sara", "role": "Auditor"}
    assert problem is None
    assert calls == [(config.AUTH_VERIFY_URL, {"Authorization": "Bearer abc"})]


@pytest.mark.parametrize("message", ["Token expired", "Invalid token", "Account is unavailable"])
def test_verify_token_returns_service1_message_when_rejected(monkeypatch, message):
    monkeypatch.setattr(
        auth.requests, "post",
        lambda url, headers, timeout: FakeResponse(401, {"status": "error", "message": message, "valid": False}),
    )
    assert REAL_VERIFY_TOKEN("Bearer abc") == (None, message)


@pytest.mark.parametrize(
    "fake_post",
    [raise_connection_error, lambda url, headers, timeout: FakeResponse(500, ValueError("not JSON"))],
    ids=["no answer", "not JSON"],
)
def test_verify_token_raises_when_service1_unavailable(monkeypatch, fake_post):
    monkeypatch.setattr(auth.requests, "post", fake_post)
    with pytest.raises(auth.AuthServiceUnavailable):
        REAL_VERIFY_TOKEN("Bearer abc")


# ---------- auth.has_valid_service_key ----------

@pytest.mark.parametrize(
    "sent_key, expected",
    [(None, False), ("", False), ("wrong-key", False), ("CORRECT", True)],
)
def test_service_key_check(monkeypatch, sent_key, expected):
    monkeypatch.setenv("INTERNAL_SERVICE_KEY", "CORRECT")
    headers = {} if sent_key is None else {"X-Service-Key": sent_key}
    with Flask(__name__).test_request_context(headers=headers):
        assert auth.has_valid_service_key() is expected


# ---------- users_client -> Service 1 GET /theana-mansour/users ----------

def test_list_users_forwards_the_callers_token(monkeypatch):
    calls = []

    def fake_get(url, headers, timeout):
        calls.append((url, headers))
        return FakeResponse(200, [{"id": 1}, {"id": 2}])

    monkeypatch.setattr(users_client.requests, "get", fake_get)

    assert REAL_LIST_USERS("Bearer admin") == [{"id": 1}, {"id": 2}]
    assert calls == [(config.USERS_LIST_URL, {"Authorization": "Bearer admin"})]


@pytest.mark.parametrize(
    "fake_get",
    [raise_connection_error, lambda url, headers, timeout: FakeResponse(403, {"status": "error"})],
    ids=["no answer", "refused"],
)
def test_list_users_raises_when_service1_unavailable(monkeypatch, fake_get):
    monkeypatch.setattr(users_client.requests, "get", fake_get)
    with pytest.raises(users_client.UsersServiceUnavailable):
        REAL_LIST_USERS("Bearer admin")


# ---------- notification_client -> Service 8 POST /sleiman-koumaira/notifications ----------

def test_send_notification_uses_the_internal_service_key(monkeypatch):
    calls = []

    def fake_post(url, json, headers, timeout):
        calls.append((url, json, headers))
        return FakeResponse(201, {"status": "success"})

    monkeypatch.setattr(notification_client.requests, "post", fake_post)
    created = REAL_SEND_NOTIFICATION(
        user_id=2, title="T", message="M", notification_type="Threat Alert", severity="High"
    )

    assert created is True
    url, body, sent_headers = calls[0]
    assert url == config.NOTIFICATIONS_URL
    assert body == {"user_id": 2, "title": "T", "message": "M", "notification_type": "Threat Alert", "severity": "High"}
    assert sent_headers == {"X-Service-Key": config.internal_service_key()}


@pytest.mark.parametrize(
    "fake_post",
    [lambda url, json, headers, timeout: FakeResponse(400, {}), raise_connection_error],
    ids=["rejected", "no answer"],
)
def test_send_notification_reports_failure(monkeypatch, fake_post):
    monkeypatch.setattr(notification_client.requests, "post", fake_post)
    assert REAL_SEND_NOTIFICATION(user_id=2, title="T", message="M", notification_type="Threat Alert", severity="High") is False


# ---------- audit_client -> Service 5 ----------

def test_audit_log_is_sent_with_service_key(monkeypatch):
    calls = []
    monkeypatch.setattr(
        audit_client.requests, "post",
        lambda url, json, headers, timeout: calls.append((url, json, headers)) or FakeResponse(201, {}),
    )
    REAL_SEND_AUDIT_LOG(user_id=1, action="CREATE_THREAT", description="d", severity="Information", related_service="S")

    url, body, sent_headers = calls[0]
    assert url == config.AUDIT_LOG_URL
    assert body == {"user_id": 1, "action": "CREATE_THREAT", "description": "d",
                    "severity": "Information", "related_service": "S"}
    assert sent_headers == {"X-Service-Key": config.internal_service_key()}


def test_audit_log_failure_does_not_crash(monkeypatch):
    monkeypatch.setattr(audit_client.requests, "post", raise_connection_error)
    REAL_SEND_AUDIT_LOG(user_id=None, action="X", description="d", severity="Warning", related_service="S")
