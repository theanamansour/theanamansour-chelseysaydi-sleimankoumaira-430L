"""
Service 2 - Asset Management Service (Sleiman Koumaira)

All SQL for the assets table lives here. Every query uses "?" placeholders, so user
input is sent to SQLite separately from the SQL text (this prevents SQL injection).
"""
from contextlib import closing

from services.assets.models import UPDATABLE_FIELDS, Asset
from shared.database import get_connection

# Search rules: these fields must match exactly...
EXACT_MATCH_FIELDS = ("asset_type", "criticality")
# ...and these only need to contain the search text (case-insensitive).
PARTIAL_MATCH_FIELDS = ("asset_name", "ip_address", "department")

# Columns written by INSERT, in order.
INSERT_COLUMNS = ("asset_name", "asset_type", "ip_address", "operating_system", "owner_id",
                  "department", "location", "criticality", "status")

# Largest number SQLite can store in an INTEGER column.
MAX_SQLITE_INTEGER = 2**63 - 1


class AssetRepository:
    """Reads and writes rows of the assets table."""

    def __init__(self, database_path):
        self.database_path = database_path

    def create(self, asset_data):
        """INSERT a new asset and return it as an Asset object (with its new ID)."""
        placeholders = ", ".join("?" for _ in INSERT_COLUMNS)
        with closing(get_connection(self.database_path)) as connection:
            cursor = connection.execute(
                f"INSERT INTO assets ({', '.join(INSERT_COLUMNS)}) VALUES ({placeholders})",
                [asset_data[column] for column in INSERT_COLUMNS],
            )
            connection.commit()
            new_id = cursor.lastrowid
        return self.get_by_id(new_id)

    def get_all(self):
        with closing(get_connection(self.database_path)) as connection:
            rows = connection.execute("SELECT * FROM assets ORDER BY asset_id").fetchall()
        return [Asset.from_row(row) for row in rows]

    def get_by_id(self, asset_id):
        """Return the Asset, or None if no row has this ID."""
        if asset_id > MAX_SQLITE_INTEGER:
            return None  # too big to ever be an ID (SQLite would raise an error)
        with closing(get_connection(self.database_path)) as connection:
            row = connection.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        return Asset.from_row(row) if row else None

    def search(self, criteria):
        """
        criteria is a dict such as {"criticality": "High", "department": "it"}.
        All given criteria must match (they are joined with AND).
        """
        conditions = []
        parameters = []
        # Column names come from our own lists above, never from the user.
        for field in EXACT_MATCH_FIELDS:
            if field in criteria:
                conditions.append(f"{field} = ?")
                parameters.append(criteria[field])
        for field in PARTIAL_MATCH_FIELDS:
            if field in criteria:
                conditions.append(f"{field} LIKE ? ESCAPE '\\'")
                parameters.append(f"%{_escape_like(criteria[field])}%")

        sql = f"SELECT * FROM assets WHERE {' AND '.join(conditions)} ORDER BY asset_id"
        with closing(get_connection(self.database_path)) as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [Asset.from_row(row) for row in rows]

    def update(self, asset_id, changes):
        """UPDATE only the fields present in changes. Returns the updated Asset, or None if not found."""
        if asset_id > MAX_SQLITE_INTEGER:
            return None
        fields = [field for field in UPDATABLE_FIELDS if field in changes]
        set_clause = ", ".join(f"{field} = ?" for field in fields)
        parameters = [changes[field] for field in fields] + [asset_id]

        with closing(get_connection(self.database_path)) as connection:
            cursor = connection.execute(f"UPDATE assets SET {set_clause} WHERE asset_id = ?", parameters)
            connection.commit()
            if cursor.rowcount == 0:
                return None
        return self.get_by_id(asset_id)

    def delete(self, asset_id):
        """DELETE the row. Returns True if a row was deleted, False if the ID did not exist."""
        if asset_id > MAX_SQLITE_INTEGER:
            return False
        with closing(get_connection(self.database_path)) as connection:
            cursor = connection.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
            connection.commit()
            return cursor.rowcount > 0


def _escape_like(text):
    """In LIKE, % and _ are wildcards. Escape them so the user's text is matched literally."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
