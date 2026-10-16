"""Tests for database/migrate_legacy_tables.py (Sleiman Koumaira)."""
import sqlite3

from database.init_db import init_database
from database.migrate_legacy_tables import migrate_tables
from tests.conftest import add_test_users


def make_old_assets_database(folder):
    """An old per-service assets.db with assets 1 and 2; asset 3 was deleted."""
    path = str(folder / "assets.db")
    init_database("assets", path)
    add_test_users(path)
    with sqlite3.connect(path) as connection:
        for name in ("Main Web Server", "HR Laptop", "Old Router"):
            connection.execute(
                "INSERT INTO assets (asset_name, asset_type, ip_address, owner_id, department, criticality)"
                " VALUES (?, 'Server', '192.0.2.10', 1, 'IT', 'High')",
                (name,),
            )
        connection.execute("DELETE FROM assets WHERE asset_id = 3")
    return path


def test_rows_keep_their_ids_and_deleted_ids_stay_unused(tmp_path):
    old_folder = tmp_path / "old"
    old_folder.mkdir()
    make_old_assets_database(old_folder)
    shared = str(tmp_path / "security_system.db")
    init_database(database_path=shared)
    add_test_users(shared)

    results = migrate_tables(source_folder=old_folder, target_path=shared)

    assert results == {"assets": (2, 0)}
    with sqlite3.connect(shared) as connection:
        names = connection.execute("SELECT asset_id, asset_name FROM assets ORDER BY asset_id").fetchall()
        assert names == [(1, "Main Web Server"), (2, "HR Laptop")]
        connection.execute(
            "INSERT INTO assets (asset_name, asset_type, ip_address, owner_id, department, criticality)"
            " VALUES ('New Server', 'Server', '192.0.2.20', 1, 'IT', 'Low')"
        )
        assert connection.execute("SELECT MAX(asset_id) FROM assets").fetchone()[0] == 4


def test_running_it_again_copies_nothing_twice(tmp_path):
    old_folder = tmp_path / "old"
    old_folder.mkdir()
    make_old_assets_database(old_folder)
    shared = str(tmp_path / "security_system.db")
    init_database(database_path=shared)
    add_test_users(shared)

    migrate_tables(source_folder=old_folder, target_path=shared)
    results = migrate_tables(source_folder=old_folder, target_path=shared)

    assert results == {"assets": (0, 2)}
