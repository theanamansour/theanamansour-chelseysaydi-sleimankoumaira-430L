
import re
import sqlite3
from getpass import getpass

from werkzeug.security import generate_password_hash

from database import get_db, init_db

init_db()

full_name = input("Full name: ").strip()
username = input("Username: ").strip()
email = input("Email: ").strip()
department = input("Department: ").strip()
password = getpass("Password: ")

if not all([full_name, username, email, department]):
    print("All fields are required.")
elif re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is None:
    print("Enter a valid email address.")
elif len(password) < 8 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
    print("Password must contain 8 characters, a letter, and a number.")
else:
    email = email.lower()
    try:
        with get_db() as db:
            existing = db.execute(
                "SELECT id FROM users "
                "WHERE username = ? COLLATE NOCASE "
                "OR email = ? COLLATE NOCASE",
                (username, email)
            ).fetchone()

            if existing is not None:
                raise sqlite3.IntegrityError

            db.execute("""
                INSERT INTO users
                (full_name, username, email, password_hash,
                 department, role, account_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                full_name, username, email,
                generate_password_hash(password),
                department, "Security Administrator", "Active"
            ))
        print("Administrator created.")
    except sqlite3.IntegrityError:
        print("Administrator could not be created: username or email already exists.")
