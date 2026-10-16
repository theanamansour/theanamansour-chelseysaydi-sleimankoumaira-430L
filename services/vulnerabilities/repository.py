"""Database access for Service 7 (table `vulnerabilities` in the shared database).

All SQL uses bound parameters. Column names in UPDATE statements come only from
the fixed list of updatable fields, never from the request.
"""
from database.connection import get_db

SELECT_VULNERABILITY = """
    SELECT v.vulnerability_id, v.vulnerability_title, v.description,
           v.cve_identifier, v.cvss_score, v.severity, v.affected_asset_id,
           a.asset_name, a.asset_type, a.criticality AS asset_criticality,
           v.discovery_source, v.status, v.created_at, v.resolution_date
    FROM vulnerabilities v
    LEFT JOIN assets a ON a.asset_id = v.affected_asset_id
"""
UPDATABLE_COLUMNS = ("description", "severity", "status", "cvss_score", "resolution_date")


def to_dict(row):
    """Shape one database row for the API, with the affected asset nested."""
    record = dict(row)
    asset = {
        "asset_id": record["affected_asset_id"],
        "asset_name": record.pop("asset_name"),
        "asset_type": record.pop("asset_type"),
        "criticality": record.pop("asset_criticality"),
    }
    ordered = {}
    for key, value in record.items():
        ordered[key] = value
        if key == "affected_asset_id":
            ordered["affected_asset"] = asset
    return ordered


class VulnerabilityRepository:
    def __init__(self, database_path=None):
        self.database_path = database_path

    def asset(self, asset_id):
        with get_db(self.database_path) as db:
            return db.execute(
                "SELECT asset_id, asset_name FROM assets WHERE asset_id = ?", (asset_id,)
            ).fetchone()

    def create(self, data):
        with get_db(self.database_path) as db:
            cursor = db.execute(
                "INSERT INTO vulnerabilities (vulnerability_title, description, "
                "cve_identifier, cvss_score, severity, affected_asset_id, discovery_source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    data["vulnerability_title"], data["description"],
                    data["cve_identifier"], data["cvss_score"], data["severity"],
                    data["affected_asset_id"], data["discovery_source"],
                ),
            )
            new_id = cursor.lastrowid
        return self.get(new_id)

    def get(self, vulnerability_id):
        with get_db(self.database_path) as db:
            row = db.execute(
                SELECT_VULNERABILITY + " WHERE v.vulnerability_id = ?",
                (vulnerability_id,),
            ).fetchone()
        return to_dict(row) if row else None

    def list_all(self):
        with get_db(self.database_path) as db:
            rows = db.execute(
                SELECT_VULNERABILITY + " ORDER BY v.vulnerability_id"
            ).fetchall()
        return [to_dict(row) for row in rows]

    def update(self, vulnerability_id, changes):
        columns = [column for column in UPDATABLE_COLUMNS if column in changes]
        if columns:
            assignments = ", ".join(f"{column} = ?" for column in columns)
            with get_db(self.database_path) as db:
                db.execute(
                    f"UPDATE vulnerabilities SET {assignments} WHERE vulnerability_id = ?",
                    [changes[column] for column in columns] + [vulnerability_id],
                )
        return self.get(vulnerability_id)

    def delete(self, vulnerability_id):
        with get_db(self.database_path) as db:
            cursor = db.execute(
                "DELETE FROM vulnerabilities WHERE vulnerability_id = ?",
                (vulnerability_id,),
            )
        return cursor.rowcount > 0

    def search(self, filters):
        conditions, params = [], []
        if "cve" in filters:
            conditions.append("v.cve_identifier LIKE ? ESCAPE '\\'")
            escaped = filters["cve"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
        if "severity" in filters:
            conditions.append("v.severity = ?")
            params.append(filters["severity"])
        if "status" in filters:
            conditions.append("v.status = ?")
            params.append(filters["status"])
        if "asset_id" in filters:
            conditions.append("v.affected_asset_id = ?")
            params.append(filters["asset_id"])
        with get_db(self.database_path) as db:
            rows = db.execute(
                SELECT_VULNERABILITY + " WHERE " + " AND ".join(conditions)
                + " ORDER BY v.vulnerability_id",
                params,
            ).fetchall()
        return [to_dict(row) for row in rows]

    def alert_recipients(self):
        """Active Security Administrators and Security Analysts get vulnerability alerts."""
        with get_db(self.database_path) as db:
            rows = db.execute(
                "SELECT id FROM users WHERE account_status = 'Active' AND role IN "
                "('Security Administrator', 'Security Analyst') ORDER BY id"
            ).fetchall()
        return [row["id"] for row in rows]
