from services.incidents.database import get_db

MAX_SQLITE_ID = 2**63 - 1


def note_to_dict(row):
    return {
        "note_id": row["note_id"],
        "incident_id": row["incident_id"],
        "analyst_id": row["analyst_id"],
        "note_content": row["note_content"],
        "created_at": row["created_at"],
    }


def incident_to_dict(row, notes=None):
    incident = {
        "incident_id": row["incident_id"],
        "title": row["title"],
        "description": row["description"],
        "category": row["category"],
        "severity": row["severity"],
        "reporter_id": row["reporter_id"],
        "asset_id": row["asset_id"],
        "assigned_analyst_id": row["assigned_analyst_id"],
        "status": row["status"],
        "created_at": row["created_at"],
        "resolution_date": row["resolution_date"],
    }
    if notes is not None:
        incident["investigation_notes"] = [note_to_dict(note) for note in notes]
    return incident


class IncidentRepository:
    def __init__(self, database_path):
        self.database_path = database_path

    def create(self, data):
        with get_db(self.database_path) as db:
            cursor = db.execute(
                """
                INSERT INTO incidents
                    (title, description, category, severity, reporter_id, asset_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    data["title"],
                    data["description"],
                    data["category"],
                    data["severity"],
                    data["reporter_id"],
                    data["asset_id"],
                ),
            )
            incident_id = cursor.lastrowid
        return self.get(incident_id)

    def all(self):
        with get_db(self.database_path) as db:
            rows = db.execute(
                "SELECT * FROM incidents ORDER BY incident_id"
            ).fetchall()
        return [incident_to_dict(row) for row in rows]

    def get(self, incident_id):
        if incident_id > MAX_SQLITE_ID:
            return None
        with get_db(self.database_path) as db:
            row = db.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                return None
            notes = db.execute(
                """
                SELECT * FROM investigation_notes
                WHERE incident_id = ? ORDER BY note_id
                """,
                (incident_id,),
            ).fetchall()
        return incident_to_dict(row, notes)

    def assign(self, incident_id, analyst_id):
        if incident_id > MAX_SQLITE_ID:
            return None
        with get_db(self.database_path) as db:
            cursor = db.execute(
                """
                UPDATE incidents SET assigned_analyst_id = ?
                WHERE incident_id = ?
                """,
                (analyst_id, incident_id),
            )
            if cursor.rowcount == 0:
                return None
        return self.get(incident_id)

    def update_status(self, incident_id, status):
        if incident_id > MAX_SQLITE_ID:
            return None
        resolution_sql = (
            "resolution_date = CURRENT_TIMESTAMP"
            if status == "Closed"
            else "resolution_date = NULL"
        )
        with get_db(self.database_path) as db:
            cursor = db.execute(
                f"""
                UPDATE incidents SET status = ?, {resolution_sql}
                WHERE incident_id = ?
                """,
                (status, incident_id),
            )
            if cursor.rowcount == 0:
                return None
        return self.get(incident_id)

    def add_note(self, incident_id, analyst_id, content):
        if incident_id > MAX_SQLITE_ID:
            return None
        with get_db(self.database_path) as db:
            exists = db.execute(
                "SELECT 1 FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if exists is None:
                return None
            cursor = db.execute(
                """
                INSERT INTO investigation_notes
                    (incident_id, analyst_id, note_content)
                VALUES (?, ?, ?)
                """,
                (incident_id, analyst_id, content),
            )
            note_id = cursor.lastrowid
            note = db.execute(
                "SELECT * FROM investigation_notes WHERE note_id = ?", (note_id,)
            ).fetchone()
        return note_to_dict(note)
