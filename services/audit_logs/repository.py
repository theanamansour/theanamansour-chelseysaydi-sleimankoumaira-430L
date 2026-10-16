from services.audit_logs.database import get_db

MAX_SQLITE_ID = 2**63 - 1


def log_to_dict(row):
    return {
        "log_id": row["log_id"],
        "user_id": row["user_id"],
        "action": row["action"],
        "description": row["description"],
        "timestamp": row["timestamp"],
        "severity": row["severity"],
        "related_service": row["related_service"],
    }


def _escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class AuditLogRepository:
    def __init__(self, database_path):
        self.database_path = database_path

    def create(self, data):
        with get_db(self.database_path) as db:
            cursor = db.execute(
                """
                INSERT INTO audit_logs
                    (user_id, action, description, severity, related_service)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    data["user_id"],
                    data["action"],
                    data["description"],
                    data["severity"],
                    data["related_service"],
                ),
            )
            log_id = cursor.lastrowid
        return self.get(log_id)

    def all(self):
        with get_db(self.database_path) as db:
            rows = db.execute(
                "SELECT * FROM audit_logs ORDER BY log_id DESC"
            ).fetchall()
        return [log_to_dict(row) for row in rows]

    def get(self, log_id):
        if log_id > MAX_SQLITE_ID:
            return None
        with get_db(self.database_path) as db:
            row = db.execute(
                "SELECT * FROM audit_logs WHERE log_id = ?", (log_id,)
            ).fetchone()
        return log_to_dict(row) if row else None

    def by_user(self, user_id):
        if user_id > MAX_SQLITE_ID:
            return []
        with get_db(self.database_path) as db:
            rows = db.execute(
                """
                SELECT * FROM audit_logs
                WHERE user_id = ? ORDER BY log_id DESC
                """,
                (user_id,),
            ).fetchall()
        return [log_to_dict(row) for row in rows]

    def search(self, criteria):
        conditions = []
        parameters = []
        if "user_id" in criteria:
            conditions.append("user_id = ?")
            parameters.append(criteria["user_id"])
        if "date" in criteria:
            conditions.append("date(timestamp) = ?")
            parameters.append(criteria["date"])
        if "severity" in criteria:
            conditions.append("severity = ?")
            parameters.append(criteria["severity"])
        for field in ("action", "related_service"):
            if field in criteria:
                conditions.append(f"{field} LIKE ? ESCAPE '\\' COLLATE NOCASE")
                parameters.append(f"%{_escape_like(criteria[field])}%")

        query = (
            f"SELECT * FROM audit_logs WHERE {' AND '.join(conditions)} "
            "ORDER BY log_id DESC"
        )
        with get_db(self.database_path) as db:
            rows = db.execute(query, parameters).fetchall()
        return [log_to_dict(row) for row in rows]

    def delete(self, log_id):
        if log_id > MAX_SQLITE_ID:
            return False
        with get_db(self.database_path) as db:
            cursor = db.execute(
                "DELETE FROM audit_logs WHERE log_id = ?", (log_id,)
            )
            return cursor.rowcount > 0
