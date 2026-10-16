import pytest

from database.connection import get_db
from database.init_db import init_database

TEST_USERS = (
    (1, "admin", "Security Administrator"),
    (2, "analyst", "Security Analyst"),
    (3, "employee", "Regular Employee"),
    (4, "auditor", "Auditor"),
    (5, "other_analyst", "Security Analyst"),
)


def seed_reference_data(database_path, asset_ids=()):
    """Create the users and assets that foreign keys in the shared schema require."""
    init_database(database_path=database_path)
    with get_db(database_path) as db:
        db.executemany(
            """
            INSERT INTO users
                (id, full_name, username, email, password_hash, department, role)
            VALUES (?, ?, ?, ?, 'not-a-real-hash', 'Security', ?)
            """,
            [
                (user_id, username.title(), username, f"{username}@example.com", role)
                for user_id, username, role in TEST_USERS
            ],
        )
        db.executemany(
            """
            INSERT INTO assets
                (asset_id, asset_name, asset_type, ip_address, owner_id,
                 department, criticality)
            VALUES (?, ?, 'Workstation', '192.0.2.10', 1, 'IT', 'Medium')
            """,
            [(asset_id, f"Test asset {asset_id}") for asset_id in asset_ids],
        )


@pytest.fixture
def seed_database():
    return seed_reference_data
