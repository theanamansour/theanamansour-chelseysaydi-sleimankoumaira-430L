
import os
import re
import secrets
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_db, init_db

app = Flask(__name__)
PREFIX = "/theana-mansour"

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"

ROLES = [ADMIN, ANALYST, EMPLOYEE, AUDITOR]
STATUSES = ["Active", "Inactive", "Suspended"]


def normalize_role(role):
    if role == "Regular User":
        return EMPLOYEE
    return role


# Keep the signing key outside GitHub.
key_file = Path(__file__).resolve().parent / ".secret_key"

if os.environ.get("SECRET_KEY"):
    secret_key = os.environ["SECRET_KEY"]
elif key_file.exists():
    secret_key = key_file.read_text().strip()
else:
    secret_key = secrets.token_hex(32)
    key_file.write_text(secret_key)

serializer = URLSafeTimedSerializer(secret_key)
init_db()


def error(message, status):
    return jsonify({"status": "error", "message": message}), status


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
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

    @staticmethod
    def by_login(login):
        with get_db() as db:
            return db.execute(
                "SELECT * FROM users WHERE username = ? OR email = ?",
                (login, login)
            ).fetchone()


def authenticate():
    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return None, error("Authentication token required", 401)

    token = header[7:].strip()

    try:
        user_id = serializer.loads(token, max_age=3600)
    except SignatureExpired:
        return None, error("Token expired", 401)
    except BadSignature:
        return None, error("Invalid token", 401)

    user = UserService.by_id(user_id)

    if user is None or user["account_status"] != "Active":
        return None, error("Account is unavailable", 401)

    return user, None


def protected(allowed_roles):
    """Require a valid token and an authorized user role."""
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            user, problem = authenticate()

            if problem:
                return problem

            if user["role"] not in allowed_roles:
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
        "password", "department"
    ]

    for field in fields:
        if not isinstance(data.get(field), str) or not data[field].strip():
            return error(f"{field} is required", 400)

    if not valid_email(data["email"]):
        return error("Invalid email format", 400)

    if not valid_password(data["password"]):
        return error(
            "Password must have at least 8 characters, "
            "including a letter and a number", 400
        )

    # Public registration always creates regular employees.
    # An administrator may register users with another role.
    
    role = normalize_role(data.get("role", EMPLOYEE))


    if role not in ROLES:
        return error("Invalid role", 400)

    if role != EMPLOYEE:
        current_user, problem = authenticate()

        if problem:
            return problem

        if current_user["role"] != ADMIN:
            return error("Only administrators can assign roles", 403)

    try:
        with get_db() as db:
            cursor = db.execute("""
                INSERT INTO users
                (full_name, username, email, password_hash,
                 department, role, account_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                data["full_name"].strip(),
                data["username"].strip(),
                data["email"].strip(),
                generate_password_hash(data["password"]),
                data["department"].strip(),
                role,
                "Active"
            ))

            user_id = cursor.lastrowid

    except __import__("sqlite3").IntegrityError:
        return error("Username or email already exists", 409)

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

    if not isinstance(login_value, str) or not isinstance(password, str):
        return error("Login and password are required", 400)

    user = UserService.by_login(login_value)

    if user is None or not check_password_hash(
        user["password_hash"], password
    ):
        return error("Invalid credentials", 401)

    if user["account_status"] != "Active":
        return error("Account is not active", 403)

    token = serializer.dumps(user["id"])

    with get_db() as db:
        db.execute(
            "UPDATE users SET last_login_at = CURRENT_TIMESTAMP "
            "WHERE id = ?",
            (user["id"],)
        )

    return jsonify({
        "message": "Login successful",
        "token": token,
        "role": user["role"],
        "user_id": user["id"]
    }), 200


# 3. UPDATE USER

@app.put(PREFIX + "/users/<int:user_id>")
@protected([ADMIN, EMPLOYEE])
def update_user(current_user, user_id):
    if current_user["role"] != ADMIN and current_user["id"] != user_id:
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

    if "email" in data and not valid_email(data["email"]):
        return error("Invalid email format", 400)

    try:
        with get_db() as db:
            for field, value in data.items():
                db.execute(
                    f"UPDATE users SET {field} = ? WHERE id = ?",
                    (value.strip(), user_id)
                )
    except __import__("sqlite3").IntegrityError:
        return error("Email already exists", 409)

    return jsonify({
        "message": "User updated successfully",
        "user": public_user(UserService.by_id(user_id))
    })


# 4. DELETE USER

@app.delete(PREFIX + "/users/<int:user_id>")
@protected([ADMIN])
def delete_user(current_user, user_id):
    if current_user["id"] == user_id:
        return error("You cannot delete your own administrator account", 403)

    if UserService.by_id(user_id) is None:
        return error("User not found", 404)

    with get_db() as db:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))

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
        if current_user["username"] != username:
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

    if not isinstance(data, dict):
        return error("Invalid role", 400)

    role = normalize_role(data.get("role"))

    if role not in ROLES:
        return error("Invalid role", 400)

    if current_user["id"] == user_id:
        return error("Cannot change your own role", 403)

    with get_db() as db:
        db.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (role, user_id)
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

    if not isinstance(data, dict) or data.get("status") not in STATUSES:
        return error("Invalid account status", 400)

    if current_user["id"] == user_id:
        return error("Cannot change your own account status", 403)

    with get_db() as db:
        db.execute(
            "UPDATE users SET account_status = ? WHERE id = ?",
            (data["status"], user_id)
        )

    return jsonify({"message": "Account status updated successfully"})



if __name__ == "__main__":
    app.run(debug=True, port=5001)
