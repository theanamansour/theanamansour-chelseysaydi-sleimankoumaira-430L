
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from services.users.audit_client import send_audit_log
from services.users.database import get_db, init_db

app = Flask(__name__)
PREFIX = "/theana-mansour"

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"

ROLES = [ADMIN, ANALYST, EMPLOYEE, AUDITOR]
STATUSES = ["Active", "Inactive", "Suspended"]
TOKEN_MAX_AGE = 3600


def normalize_role(role):
    if isinstance(role, str):
        role = role.strip()
    if role == "Regular User":
        return EMPLOYEE
    return role


# Keep the signing key outside GitHub.
key_file = Path(__file__).resolve().parent / ".secret_key"

if os.environ.get("JWT_SECRET_KEY"):
    secret_key = os.environ["JWT_SECRET_KEY"]
elif os.environ.get("SECRET_KEY"):
    # Backward-compatible local configuration name.
    secret_key = os.environ["SECRET_KEY"]
elif key_file.exists():
    secret_key = key_file.read_text().strip()
else:
    secret_key = secrets.token_hex(32)
    key_file.write_text(secret_key)

init_db()


def error(message, status):
    return jsonify({"status": "error", "message": message}), status


def no_store(response):
    """Prevent authentication responses from being cached."""
    response.headers["Cache-Control"] = "no-store"
    return response


def public_user(user):
    """Convert a database row to JSON without the password hash."""
    return {
        "id": user["id"],
        "full_name": user["full_name"],
        "username": user["username"],
        "email": user["email"],
        "department": user["department"],
        "role": user["role"],
        "account_status": user["account_status"],
        "created_at": user["created_at"],
        "last_login_at": user["last_login_at"]
    }


def valid_email(email):
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None


def valid_password(password):
    return (
        len(password) >= 8
        and any(char.isalpha() for char in password)
        and any(char.isdigit() for char in password)
    )


class UserService:

    @staticmethod
    def by_id(user_id):
        with get_db() as db:
            return db.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()

    @staticmethod
    def by_username(username):
        with get_db() as db:
            return db.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (username,)
            ).fetchone()

    @staticmethod
    def by_login(login):
        with get_db() as db:
            return db.execute(
                "SELECT * FROM users "
                "WHERE username = ? COLLATE NOCASE "
                "OR email = ? COLLATE NOCASE",
                (login, login)
            ).fetchone()

    @staticmethod
    def registration_conflict(username, email):
        with get_db() as db:
            return db.execute(
                "SELECT username, email FROM users "
                "WHERE username = ? COLLATE NOCASE "
                "OR email = ? COLLATE NOCASE",
                (username, email)
            ).fetchone()

    @staticmethod
    def email_in_use(email, excluding_user_id):
        with get_db() as db:
            return db.execute(
                "SELECT id FROM users "
                "WHERE email = ? COLLATE NOCASE AND id != ?",
                (email, excluding_user_id)
            ).fetchone() is not None


def authenticate():
    header = request.headers.get("Authorization", "")

    scheme, separator, token = header.partition(" ")
    token = token.strip()

    if scheme.lower() != "bearer" or not separator or not token:
        return None, error("Authentication token required", 401)

    try:
        claims = jwt.decode(
            token,
            secret_key,
            algorithms=["HS256"],
            options={"require": ["sub", "user_id", "iat", "exp"]}
        )
    except jwt.ExpiredSignatureError:
        return None, error("Token expired", 401)
    except jwt.InvalidTokenError:
        return None, error("Invalid token", 401)

    user_id = claims.get("user_id")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        return None, error("Invalid token", 401)

    if claims.get("sub") != str(user_id):
        return None, error("Invalid token", 401)

    user = UserService.by_id(user_id)

    if user is None or user["account_status"] != "Active":
        return None, error("Account is unavailable", 401)

    return user, None


# Verify authentication token for other services
@app.post(PREFIX + "/auth/verify")
def verify_token():
    user, problem = authenticate()

    if problem:
        response, status = problem
        payload = response.get_json()
        payload["valid"] = False
        return no_store(jsonify(payload)), status

    response = jsonify({
        "valid": True,
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"]
    })
    return no_store(response), 200


def protected(allowed_roles):
    """Require a valid token and an authorized user role."""
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            user, problem = authenticate()

            if problem:
                send_audit_log(
                    None,
                    "UNAUTHENTICATED_ACCESS",
                    f"{request.method} {request.path} rejected: authentication failed",
                    "Warning"
                )
                return problem

            if user["role"] not in allowed_roles:
                send_audit_log(
                    user["id"],
                    "PERMISSION_DENIED",
                    f"{user['role']} attempted {request.method} {request.path}",
                    "Warning"
                )
                return error("Permission denied", 403)

            return function(user, *args, **kwargs)
        return wrapper
    return decorator


# 1. REGISTER USER

@app.post(PREFIX + "/users/register")
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    fields = [
        "full_name", "username", "email",
        "password", "department", "role"
    ]

    for field in fields:
        if not isinstance(data.get(field), str) or not data[field].strip():
            return error(f"{field} is required", 400)

    full_name = data["full_name"].strip()
    username = data["username"].strip()
    email = data["email"].strip().lower()
    password = data["password"]
    department = data["department"].strip()
    role = normalize_role(data["role"])

    if not valid_email(email):
        return error("Invalid email format", 400)

    if not valid_password(password):
        return error(
            "Password must have at least 8 characters, "
            "including a letter and a number", 400
        )

    # Public registration always creates regular employees.
    # An administrator may register users with another role.
    actor_id = None

    if role not in ROLES:
        return error("Invalid role", 400)

    if role != EMPLOYEE:
        current_user, problem = authenticate()

        if problem:
            send_audit_log(
                None,
                "UNAUTHENTICATED_ACCESS",
                f"Attempted to register a user with privileged role {role}",
                "Warning"
            )
            return problem

        if current_user["role"] != ADMIN:
            send_audit_log(
                current_user["id"],
                "PERMISSION_DENIED",
                f"Attempted to register a user with privileged role {role}",
                "Warning"
            )
            return error("Only administrators can assign roles", 403)
        actor_id = current_user["id"]

    conflict = UserService.registration_conflict(username, email)

    if conflict is not None:
        if conflict["username"].casefold() == username.casefold():
            return error("Username already exists", 409)
        return error("Email already exists", 409)

    try:
        with get_db() as db:
            cursor = db.execute("""
                INSERT INTO users
                (full_name, username, email, password_hash,
                 department, role, account_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                full_name,
                username,
                email,
                generate_password_hash(password),
                department,
                role,
                "Active"
            ))

            user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        return error("Username or email already exists", 409)

    send_audit_log(
        actor_id or user_id,
        "REGISTER_USER",
        f"User account '{username}' was registered with role {role}"
    )

    return jsonify({
        "message": "User registered successfully",
        "user_id": user_id,
        "role": role
    }), 201


# 2. LOGIN

@app.post(PREFIX + "/users/login")
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    login_value = data.get("login")
    password = data.get("password")

    if (
        not isinstance(login_value, str)
        or not login_value.strip()
        or not isinstance(password, str)
        or not password
    ):
        return error("Login and password are required", 400)

    user = UserService.by_login(login_value.strip())

    if user is None or not check_password_hash(
        user["password_hash"], password
    ):
        send_audit_log(
            None,
            "LOGIN_FAILED",
            f"Failed login attempt for '{login_value.strip()}'",
            "Warning"
        )
        return error("Invalid credentials", 401)

    if user["account_status"] != "Active":
        send_audit_log(
            user["id"],
            "LOGIN_BLOCKED",
            f"Login blocked because account status is {user['account_status']}",
            "Warning"
        )
        return error("Account is not active", 403)

    issued_at = datetime.now(timezone.utc)
    token = jwt.encode({
        "sub": str(user["id"]),
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "iat": issued_at,
        "exp": issued_at + timedelta(seconds=TOKEN_MAX_AGE)
    }, secret_key, algorithm="HS256")

    with get_db() as db:
        db.execute(
            "UPDATE users SET last_login_at = CURRENT_TIMESTAMP "
            "WHERE id = ?",
            (user["id"],)
        )

    send_audit_log(
        user["id"],
        "LOGIN_SUCCESS",
        f"User '{user['username']}' authenticated successfully"
    )

    response = jsonify({
        "message": "Login successful",
        "token": token,
        "role": user["role"],
        "user_id": user["id"]
    })
    return no_store(response), 200


# 3. UPDATE USER

@app.put(PREFIX + "/users/<int:user_id>")
@protected([ADMIN, EMPLOYEE])
def update_user(current_user, user_id):
    if current_user["role"] != ADMIN and current_user["id"] != user_id:
        send_audit_log(
            current_user["id"],
            "PERMISSION_DENIED",
            f"Attempted to update user {user_id}",
            "Warning"
        )
        return error("You may only update your own profile", 403)

    if UserService.by_id(user_id) is None:
        return error("User not found", 404)

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("A JSON object is required", 400)

    fields = ["full_name", "email", "department"]

    if not data or any(field not in fields for field in data):
        return error("Invalid update fields", 400)

    if any(
        not isinstance(value, str) or not value.strip()
        for value in data.values()
    ):
        return error("Update values cannot be empty", 400)

    if "email" in data:
        email = data["email"].strip().lower()
        if not valid_email(email):
            return error("Invalid email format", 400)
        if UserService.email_in_use(email, user_id):
            return error("Email already exists", 409)
        data["email"] = email

    try:
        with get_db() as db:
            for field, value in data.items():
                db.execute(
                    f"UPDATE users SET {field} = ? WHERE id = ?",
                    (value.strip(), user_id)
                )
    except sqlite3.IntegrityError:
        return error("Email already exists", 409)

    send_audit_log(
        current_user["id"],
        "UPDATE_USER",
        f"Updated user {user_id}: {', '.join(sorted(data))}"
    )

    return jsonify({
        "message": "User updated successfully",
        "user": public_user(UserService.by_id(user_id))
    })


# 4. DELETE USER

@app.delete(PREFIX + "/users/<int:user_id>")
@protected([ADMIN])
def delete_user(current_user, user_id):
    if current_user["id"] == user_id:
        send_audit_log(
            current_user["id"],
            "PERMISSION_DENIED",
            "Administrator attempted to delete their own account",
            "Warning"
        )
        return error("You cannot delete your own administrator account", 403)

    if UserService.by_id(user_id) is None:
        return error("User not found", 404)

    try:
        with get_db() as db:
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    except sqlite3.IntegrityError:
        return error(
            "User cannot be deleted while related system records exist", 409
        )

    send_audit_log(
        current_user["id"],
        "DELETE_USER",
        f"Deleted user {user_id}",
        "Warning"
    )

    return jsonify({"message": "User deleted successfully"})


# 5. RETRIEVE ALL USERS

@app.get(PREFIX + "/users")
@protected([ADMIN, AUDITOR])
def get_users(current_user):
    with get_db() as db:
        users = db.execute("SELECT * FROM users").fetchall()

    return jsonify([public_user(user) for user in users])


# 6. RETRIEVE USER BY USERNAME

@app.get(PREFIX + "/users/<username>")
@protected([ADMIN, EMPLOYEE, AUDITOR])
def get_user(current_user, username):
    if current_user["role"] == EMPLOYEE:
        if current_user["username"].casefold() != username.casefold():
            send_audit_log(
                current_user["id"],
                "PERMISSION_DENIED",
                f"Attempted to view user '{username}'",
                "Warning"
            )
            return error("You may only view your own profile", 403)

    user = UserService.by_username(username)

    if user is None:
        return error("User not found", 404)

    return jsonify(public_user(user))


# ADMINISTRATOR ROLE MANAGEMENT

@app.put(PREFIX + "/users/<int:user_id>/role")
@protected([ADMIN])
def update_role(current_user, user_id):
    user = UserService.by_id(user_id)

    if user is None:
        return error("User not found", 404)

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or set(data) != {"role"}:
        return error("Invalid role", 400)

    role = normalize_role(data.get("role"))

    if role not in ROLES:
        return error("Invalid role", 400)

    if current_user["id"] == user_id:
        send_audit_log(
            current_user["id"],
            "PERMISSION_DENIED",
            "Administrator attempted to change their own role",
            "Warning"
        )
        return error("Cannot change your own role", 403)

    with get_db() as db:
        db.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (role, user_id)
        )

    send_audit_log(
        current_user["id"],
        "UPDATE_USER_ROLE",
        f"Changed user {user_id} role from {user['role']} to {role}",
        "Warning"
    )

    return jsonify({"message": "User role updated successfully"})


# ADMINISTRATOR ACCOUNT STATUS MANAGEMENT
@app.put(PREFIX + "/users/<int:user_id>/status")
@protected([ADMIN])
def update_status(current_user, user_id):
    user = UserService.by_id(user_id)

    if user is None:
        return error("User not found", 404)

    data = request.get_json(silent=True)

    if not isinstance(data, dict) or set(data) != {"status"}:
        return error("Invalid account status", 400)

    status = data["status"].strip() if isinstance(data["status"], str) else None

    if status not in STATUSES:
        return error("Invalid account status", 400)

    if current_user["id"] == user_id:
        send_audit_log(
            current_user["id"],
            "PERMISSION_DENIED",
            "Administrator attempted to change their own account status",
            "Warning"
        )
        return error("Cannot change your own account status", 403)

    with get_db() as db:
        db.execute(
            "UPDATE users SET account_status = ? WHERE id = ?",
            (status, user_id)
        )

    send_audit_log(
        current_user["id"],
        "UPDATE_ACCOUNT_STATUS",
        f"Changed user {user_id} account status from "
        f"{user['account_status']} to {status}",
        "Warning" if status != "Active" else "Information"
    )

    return jsonify({"message": "Account status updated successfully"})


@app.errorhandler(404)
def route_not_found(_exception):
    return error("Resource not found", 404)


@app.errorhandler(405)
def method_not_allowed(_exception):
    return error("Method not allowed", 405)


@app.errorhandler(500)
def internal_error(_exception):
    return error("Internal server error", 500)



if __name__ == "__main__":
    port = int(os.environ.get("USER_SERVICE_PORT", "5001"))
    app.run(host="127.0.0.1", debug=True, port=port)
