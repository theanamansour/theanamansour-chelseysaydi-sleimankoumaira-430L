"""
Service 4 - Threat Intelligence Service (Sleiman Koumaira)

All SQL for the threats table lives here. Every query uses "?" placeholders: the
values are sent to SQLite separately from the SQL text, so user input can never
change the meaning of a query (this is what prevents SQL injection).
"""
from database.connection import get_db  # the team's shared database (foreign keys on)
from services.threats.models import UPDATABLE_FIELDS, Threat

# Search rules: these fields must match exactly...
EXACT_MATCH_FIELDS = ("threat_type", "severity")
# ...and these only need to contain the search text (case-insensitive).
PARTIAL_MATCH_FIELDS = ("threat_value", "source")

# Largest number SQLite can store in an INTEGER column.
MAX_SQLITE_INTEGER = 2**63 - 1


class ThreatRepository:
    """Reads and writes rows of the threats table."""

    def __init__(self, database_path):
        self.database_path = database_path

    def create(self, threat_data):
        """INSERT a new threat and return it as a Threat object (with its new ID and date)."""
        with get_db(self.database_path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO threats (threat_type, threat_value, description, severity, source)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    threat_data["threat_type"],
                    threat_data["threat_value"],
                    threat_data["description"],
                    threat_data["severity"],
                    threat_data["source"],
                ),
            )
            new_id = cursor.lastrowid
        return self.get_by_id(new_id)

    def get_all(self):
        with get_db(self.database_path) as connection:
            rows = connection.execute("SELECT * FROM threats ORDER BY threat_id").fetchall()
        return [Threat.from_row(row) for row in rows]

    def get_by_id(self, threat_id):
        """Return the Threat, or None if no row has this ID."""
        if threat_id > MAX_SQLITE_INTEGER:
            return None  # too big to ever be an ID (SQLite would raise an error)
        with get_db(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM threats WHERE threat_id = ?", (threat_id,)
            ).fetchone()
        return Threat.from_row(row) if row else None

    def find_by_type_and_value(self, threat_type, threat_value):
        """Used to detect duplicates before inserting."""
        with get_db(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM threats WHERE threat_type = ? AND threat_value = ?",
                (threat_type, threat_value),
            ).fetchone()
        return Threat.from_row(row) if row else None

    def search(self, criteria):
        """
        criteria is a dict such as {"severity": "High", "source": "abuse"}.
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

        sql = f"SELECT * FROM threats WHERE {' AND '.join(conditions)} ORDER BY threat_id"
        with get_db(self.database_path) as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [Threat.from_row(row) for row in rows]

    def update(self, threat_id, changes):
        """UPDATE only the fields present in changes. Returns the updated Threat, or None if not found."""
        fields = [field for field in UPDATABLE_FIELDS if field in changes]
        set_clause = ", ".join(f"{field} = ?" for field in fields)
        parameters = [changes[field] for field in fields] + [threat_id]

        with get_db(self.database_path) as connection:
            cursor = connection.execute(
                f"UPDATE threats SET {set_clause} WHERE threat_id = ?", parameters
            )
            if cursor.rowcount == 0:
                return None
        return self.get_by_id(threat_id)

    def delete(self, threat_id):
        """DELETE the row. Returns True if a row was deleted, False if the ID did not exist."""
        with get_db(self.database_path) as connection:
            cursor = connection.execute("DELETE FROM threats WHERE threat_id = ?", (threat_id,))
            return cursor.rowcount > 0


def _escape_like(text):
    """In LIKE, % and _ are wildcards. Escape them so the user's text is matched literally."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
