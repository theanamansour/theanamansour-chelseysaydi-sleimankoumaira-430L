"""Service 1 (Users and Identity Management) tests - Theana Mansour.

Run from the repository root:  python -m pytest -q tests/test_user_service.py

The environment is set before the app is imported, so the tests use a temporary
shared database, never write .secret_key or .internal_service_key into the repo,
and send audit events to a small fake Service 5 started inside the test run.
"""
import json
import os
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ---------- fake Service 5 (audit log) ----------
AUDIT_EVENTS = []
STUB = {"status": 201, "delay": 0}


class AuditHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if STUB["delay"]:
            time.sleep(STUB["delay"])
        AUDIT_EVENTS.append({"path": self.path, "key": self.headers.get("X-Service-Key"),
                             "json": json.loads(body)})
        self.send_response(STUB["status"])
        self.end_headers()

    def log_message(self, *args):
        pass


_server = HTTPServer(("127.0.0.1", 0), AuditHandler)
threading.Thread(target=_server.serve_forever, daemon=True).start()

TMP = Path(tempfile.mkdtemp(prefix="svc1-"))
DB_PATH = TMP / "security_system.db"
SECRET = "test-secret-" + "x" * 40
SERVICE_KEY = "test-internal-service-key"
os.environ.update({
    "SYSTEM_DATABASE_PATH": str(DB_PATH),
    "JWT_SECRET_KEY": SECRET,
    "INTERNAL_SERVICE_KEY": SERVICE_KEY,
    "AUDIT_LOG_URL": f"http://127.0.0.1:{_server.server_port}/chelsea-saydi/logs",
})
os.environ.pop("AUDIT_LOG_DISABLED", None)

import jwt  # noqa: E402
import pytest  # noqa: E402

import database.connection  # noqa: E402
import services.users.audit_client as audit_client  # noqa: E402
import services.users.database as users_db  # noqa: E402
from services.users import app as app_module  # noqa: E402

P = "/theana-mansour"
PASSWORD = "Passw0rd!"


@pytest.fixture(scope="module")
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def make_admin(username="admin"):
    from werkzeug.security import generate_password_hash
    with database.connection.get_db() as db:
        db.execute("INSERT INTO users (full_name, username, email, password_hash, department, role)"
                   " VALUES (?, ?, ?, ?, 'IT', 'Security Administrator')",
                   (username.title(), username, f"{username}@corp.com", generate_password_hash(PASSWORD)))


def login(client, who):
    r = client.post(P + "/users/login", json={"login": who, "password": PASSWORD})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def register(client, username, role="Regular Employee", token=None, **extra):
    body = {"full_name": username.title(), "username": username, "email": f"{username}@corp.com",
            "password": PASSWORD, "department": "IT", "role": role}
    body.update(extra)
    return client.post(P + "/users/register", json=body, headers=auth(token) if token else {})


def uid(username):
    with database.connection.get_db() as db:
        return db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


@pytest.fixture(scope="module")
def tokens(client):
    make_admin("admin")
    admin = login(client, "admin")
    assert register(client, "analyst", "Security Analyst", admin).status_code == 201
    assert register(client, "auditor", "Auditor", admin).status_code == 201
    assert register(client, "employee").status_code == 201
    assert register(client, "employee2").status_code == 201
    return {name: login(client, name) for name in ("admin", "analyst", "auditor", "employee", "employee2")}


# ---------- shared database wiring ----------
def test_service1_uses_shared_database_package():
    assert users_db.get_db is database.connection.get_db
    assert app_module.get_db is database.connection.get_db
    assert DB_PATH.exists()  # created at import via init_db() at SYSTEM_DATABASE_PATH
    with sqlite3.connect(DB_PATH) as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "assets", "audit_logs"} <= names
    with database.connection.get_db() as db:
        assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_no_secret_files_written_into_repo():
    root = Path(app_module.__file__).resolve().parents[2]
    assert not (root / "services" / "users" / ".secret_key").exists()
    assert not (root / ".internal_service_key").exists()
    assert app_module.secret_key == SECRET


# ---------- registration validation ----------
@pytest.mark.parametrize("body,status", [
    (None, 400),
    ({"username": "x"}, 400),
])
def test_register_requires_json_and_fields(client, body, status):
    r = client.post(P + "/users/register", data="not json", content_type="text/plain") if body is None \
        else client.post(P + "/users/register", json=body)
    assert r.status_code == status


def test_register_validation(client, tokens):
    assert register(client, "bademail", email="nope").status_code == 400
    assert register(client, "weakpw", password="short1").status_code == 400
    assert register(client, "nodigit", password="abcdefghij").status_code == 400
    assert register(client, "badrole", role="Superuser").status_code == 400
    r = register(client, "EMPLOYEE")  # case-insensitive duplicate username
    assert r.status_code == 409 and r.get_json()["message"] == "Username already exists"
    r = register(client, "newname", email="Employee@corp.com")
    assert r.status_code == 409 and r.get_json()["message"] == "Email already exists"


def test_regular_user_alias_normalised_on_register(client, tokens):
    r = register(client, "aliasuser", role="Regular User")
    assert r.status_code == 201 and r.get_json()["role"] == "Regular Employee"
    r = register(client, "aliasuser2", role="  Regular User  ")
    assert r.status_code == 201 and r.get_json()["role"] == "Regular Employee"


def test_privileged_registration_requires_admin(client, tokens):
    assert register(client, "priv1", "Security Analyst").status_code == 401
    assert register(client, "priv2", "Security Analyst", tokens["employee"]).status_code == 403
    assert register(client, "priv3", "Auditor", tokens["analyst"]).status_code == 403
    assert register(client, "priv4", "Auditor", tokens["admin"]).status_code == 201


# ---------- login + JWT ----------
def test_login_by_username_or_email_and_jwt_shape(client, tokens):
    r = client.post(P + "/users/login", json={"login": "EMPLOYEE@corp.com", "password": PASSWORD})
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    token = r.get_json()["token"]
    assert jwt.get_unverified_header(token)["alg"] == "HS256"
    claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    assert claims["exp"] - claims["iat"] == 3600
    assert claims["sub"] == str(claims["user_id"]) and claims["role"] == "Regular Employee"
    assert client.post(P + "/users/login", json={"login": "employee", "password": "Wrong123"}).status_code == 401
    assert client.post(P + "/users/login", json={"login": "", "password": ""}).status_code == 400


def test_verify_returns_exact_fields(client, tokens):
    r = client.post(P + "/auth/verify", headers=auth(tokens["analyst"]))
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    assert r.get_json() == {"valid": True, "user_id": uid("analyst"), "username": "analyst",
                            "role": "Security Analyst"}


def _forge(secret=SECRET, **overrides):
    now = datetime.now(timezone.utc)
    claims = {"sub": str(uid("employee")), "user_id": uid("employee"), "username": "employee",
              "role": "Regular Employee", "iat": now, "exp": now + timedelta(hours=1)}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, secret, algorithm="HS256")


@pytest.mark.parametrize("header", [
    None,
    "Bearer",
    "Basic abc",
    "Bearer not-a-jwt",
])
def test_verify_rejects_missing_or_malformed(client, header):
    r = client.post(P + "/auth/verify", headers={"Authorization": header} if header else {})
    assert r.status_code == 401 and r.get_json()["valid"] is False


def test_verify_rejects_bad_tokens(client, tokens):
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    bad = {
        "expired": _forge(iat=past, exp=past + timedelta(hours=1)),
        "wrong_key": _forge(secret="another-secret-" + "y" * 40),
        "missing_exp": _forge(exp=None),
        "sub_mismatch": _forge(sub="999"),
        "user_id_string": _forge(user_id="1"),
        "alg_none": jwt.encode({"sub": "1", "user_id": 1, "iat": 1, "exp": 9999999999}, None, algorithm="none"),
    }
    for name, token in bad.items():
        r = client.post(P + "/auth/verify", headers=auth(token))
        assert r.status_code == 401 and r.get_json()["valid"] is False, name
    assert client.post(P + "/auth/verify", headers=auth(_forge())).status_code == 200


# ---------- account status ----------
def test_suspended_and_deleted_users_become_invalid(client, tokens):
    assert register(client, "victim").status_code == 201
    victim_token = login(client, "victim")
    victim = uid("victim")
    assert client.post(P + "/auth/verify", headers=auth(victim_token)).status_code == 200
    r = client.put(P + f"/users/{victim}/status", json={"status": "Suspended"}, headers=auth(tokens["admin"]))
    assert r.status_code == 200
    assert client.post(P + "/auth/verify", headers=auth(victim_token)).get_json()["valid"] is False
    assert client.post(P + "/users/login", json={"login": "victim", "password": PASSWORD}).status_code == 403
    client.put(P + f"/users/{victim}/status", json={"status": "Inactive"}, headers=auth(tokens["admin"]))
    assert client.post(P + "/users/login", json={"login": "victim", "password": PASSWORD}).status_code == 403
    client.put(P + f"/users/{victim}/status", json={"status": "Active"}, headers=auth(tokens["admin"]))
    assert client.post(P + "/auth/verify", headers=auth(victim_token)).status_code == 200
    assert client.delete(P + f"/users/{victim}", headers=auth(tokens["admin"])).status_code == 200
    assert client.post(P + "/auth/verify", headers=auth(victim_token)).status_code == 401


def test_status_validation(client, tokens):
    emp = uid("employee2")
    h = auth(tokens["admin"])
    assert client.put(P + f"/users/{emp}/status", json={"status": "Gone"}, headers=h).status_code == 400
    assert client.put(P + f"/users/{emp}/status", json={"status": 5}, headers=h).status_code == 400
    assert client.put(P + f"/users/{emp}/status", json={"status": "Active", "x": 1}, headers=h).status_code == 400
    assert client.put(P + f"/users/{uid('admin')}/status", json={"status": "Suspended"}, headers=h).status_code == 403
    assert client.put(P + "/users/99999/status", json={"status": "Active"}, headers=h).status_code == 404
    assert client.put(P + f"/users/{emp}/status", json={"status": "Active"},
                      headers=auth(tokens["employee"])).status_code == 403


# ---------- RBAC ----------
def test_list_users_rbac(client, tokens):
    for who, status in [("admin", 200), ("auditor", 200), ("analyst", 403), ("employee", 403)]:
        r = client.get(P + "/users", headers=auth(tokens[who]))
        assert r.status_code == status, who
    users = client.get(P + "/users", headers=auth(tokens["admin"])).get_json()
    assert users and all("password_hash" not in u for u in users)
    assert client.get(P + "/users").status_code == 401


def test_get_user_rbac(client, tokens):
    assert client.get(P + "/users/employee", headers=auth(tokens["employee"])).status_code == 200
    assert client.get(P + "/users/EMPLOYEE", headers=auth(tokens["employee"])).status_code == 200
    assert client.get(P + "/users/admin", headers=auth(tokens["employee"])).status_code == 403
    assert client.get(P + "/users/employee", headers=auth(tokens["auditor"])).status_code == 200
    assert client.get(P + "/users/employee", headers=auth(tokens["admin"])).status_code == 200
    assert client.get(P + "/users/employee", headers=auth(tokens["analyst"])).status_code == 403
    assert client.get(P + "/users/nobody", headers=auth(tokens["admin"])).status_code == 404


def test_update_user_rbac_and_validation(client, tokens):
    me = uid("employee")
    other = uid("employee2")
    r = client.put(P + f"/users/{me}", json={"department": "Finance"}, headers=auth(tokens["employee"]))
    assert r.status_code == 200 and r.get_json()["user"]["department"] == "Finance"
    assert "password_hash" not in r.get_json()["user"]
    assert client.put(P + f"/users/{other}", json={"department": "X"}, headers=auth(tokens["employee"])).status_code == 403
    assert client.put(P + f"/users/{other}", json={"department": "Ops"}, headers=auth(tokens["admin"])).status_code == 200
    assert client.put(P + f"/users/{me}", json={"role": "Security Administrator"},
                      headers=auth(tokens["employee"])).status_code == 400
    assert client.put(P + f"/users/{me}", json={"email": "bad"}, headers=auth(tokens["employee"])).status_code == 400
    assert client.put(P + f"/users/{me}", json={"email": "ANALYST@corp.com"},
                      headers=auth(tokens["employee"])).status_code == 409
    assert client.put(P + f"/users/{me}", json={"full_name": "  "}, headers=auth(tokens["employee"])).status_code == 400
    assert client.put(P + f"/users/{me}", json={}, headers=auth(tokens["employee"])).status_code == 400
    assert client.put(P + f"/users/{me}", json={"department": "X"}, headers=auth(tokens["analyst"])).status_code == 403
    assert client.put(P + f"/users/{me}", json={"department": "X"}, headers=auth(tokens["auditor"])).status_code == 403
    assert client.put(P + "/users/99999", json={"department": "X"}, headers=auth(tokens["admin"])).status_code == 404


def test_role_update_rbac_and_alias(client, tokens):
    h = auth(tokens["admin"])
    assert register(client, "promote").status_code == 201
    target = uid("promote")
    assert client.put(P + f"/users/{target}/role", json={"role": "Security Analyst"}, headers=h).status_code == 200
    r = client.put(P + f"/users/{target}/role", json={"role": "Regular User"}, headers=h)
    assert r.status_code == 200
    assert client.get(P + "/users/promote", headers=h).get_json()["role"] == "Regular Employee"
    assert client.put(P + f"/users/{target}/role", json={"role": "Boss"}, headers=h).status_code == 400
    assert client.put(P + f"/users/{target}/role", json={"role": "Auditor", "x": 1}, headers=h).status_code == 400
    assert client.put(P + f"/users/{uid('admin')}/role", json={"role": "Auditor"}, headers=h).status_code == 403
    assert client.put(P + f"/users/{target}/role", json={"role": "Auditor"},
                      headers=auth(tokens["analyst"])).status_code == 403


def test_delete_rbac_self_and_missing(client, tokens):
    assert register(client, "todelete").status_code == 201
    target = uid("todelete")
    assert client.delete(P + f"/users/{target}", headers=auth(tokens["employee"])).status_code == 403
    assert client.delete(P + f"/users/{target}", headers=auth(tokens["auditor"])).status_code == 403
    assert client.delete(P + f"/users/{uid('admin')}", headers=auth(tokens["admin"])).status_code == 403
    assert client.delete(P + "/users/99999", headers=auth(tokens["admin"])).status_code == 404
    assert client.delete(P + f"/users/{target}", headers=auth(tokens["admin"])).status_code == 200


def test_delete_blocked_by_foreign_key_returns_409(client, tokens):
    assert register(client, "assetowner").status_code == 201
    owner = uid("assetowner")
    with database.connection.get_db() as db:
        db.execute("INSERT INTO assets (asset_name, asset_type, ip_address, owner_id, department, criticality)"
                   " VALUES ('srv', 'Server', '10.0.0.5', ?, 'IT', 'High')", (owner,))
    r = client.delete(P + f"/users/{owner}", headers=auth(tokens["admin"]))
    assert r.status_code == 409
    assert client.get(P + "/users/assetowner", headers=auth(tokens["admin"])).status_code == 200


def test_unknown_route_and_method(client):
    assert client.get(P + "/nothing/here/at/all").status_code == 404
    assert client.patch(P + "/users/login").status_code == 405


# ---------- audit integration ----------
def test_audit_events_are_sent_with_service_key(client, tokens):
    AUDIT_EVENTS.clear()
    assert register(client, "audited").status_code == 201
    client.post(P + "/users/login", json={"login": "audited", "password": "Wrong123"})
    client.get(P + "/users", headers=auth(tokens["employee"]))
    actions = [e["json"]["action"] for e in AUDIT_EVENTS]
    assert {"REGISTER_USER", "LOGIN_FAILED", "PERMISSION_DENIED"} <= set(actions)
    for e in AUDIT_EVENTS:
        assert e["path"] == "/chelsea-saydi/logs"
        assert e["key"] == SERVICE_KEY
        assert e["json"]["related_service"] == "Users and Identity Management Service"
        assert set(e["json"]) == {"user_id", "action", "description", "severity", "related_service"}


def test_audit_failures_never_break_user_operations(client, tokens, monkeypatch):
    # Service 5 down (connection refused)
    monkeypatch.setattr(audit_client, "AUDIT_LOG_URL", "http://127.0.0.1:9/chelsea-saydi/logs")
    assert register(client, "down1").status_code == 201
    assert login(client, "down1")
    # Service 5 returns an error
    monkeypatch.setattr(audit_client, "AUDIT_LOG_URL", f"http://127.0.0.1:{_server.server_port}/chelsea-saydi/logs")
    STUB["status"] = 500
    assert register(client, "err500").status_code == 201
    # Service 5 too slow
    STUB.update(status=201, delay=1.0)
    monkeypatch.setattr(audit_client, "REQUEST_TIMEOUT", 0.2)
    assert register(client, "slow1").status_code == 201
    STUB["delay"] = 0
    # Audit disabled explicitly
    monkeypatch.setenv("AUDIT_LOG_DISABLED", "1")
    assert audit_client.send_audit_log(None, "X", "y") is False
    assert register(client, "disabled1").status_code == 201


def test_field_lengths_return_400_not_409(client, tokens):
    r = register(client, "ab")
    assert r.status_code == 400 and "username" in r.get_json()["message"]
    assert register(client, "u" * 51).status_code == 400
    assert register(client, "longname", full_name="x" * 151).status_code == 400
    assert register(client, "longdept", department="d" * 101).status_code == 400
    assert register(client, "abc").status_code == 201  # 3 characters is the minimum
    me = uid("employee")
    r = client.put(P + f"/users/{me}", json={"department": "d" * 101}, headers=auth(tokens["employee"]))
    assert r.status_code == 400


def test_sql_injection_text_is_treated_as_data(client, tokens):
    r = client.post(P + "/users/login", json={"login": "admin' OR '1'='1", "password": "x"})
    assert r.status_code == 401
    r = client.get(P + "/users/admin' OR '1'='1", headers=auth(tokens["admin"]))
    assert r.status_code == 404
