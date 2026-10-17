"""Read-only report queries over the shared security database.

Each report reads the tables owned by the other services:

- users            -> Service 1, Users and Identity Management
- assets           -> Service 2, Asset Management
- incidents        -> Service 3, Incident Management
- threats          -> Service 4, Threat Intelligence
- audit_logs       -> Service 5, Security Audit Logging
- vulnerabilities  -> Service 7, Vulnerability Management

Only SELECT statements are used, and every value from the request is passed as
a bound parameter, so reports can never change or inject into the data.
"""
from database.connection import get_db

SEVERITIES = ("Low", "Medium", "High", "Critical")
INCIDENT_STATUSES = ("Open", "Under Investigation", "Mitigated", "Resolved", "Closed")
VULNERABILITY_STATUSES = ("Open", "Under Investigation", "In Progress", "Resolved", "Closed")
FINISHED_STATUSES = ("Resolved", "Closed")
ASSET_TYPES = (
    "Server", "Workstation", "Database", "Application",
    "Network Device", "Cloud Resource",
)
ASSET_STATUSES = ("Active", "Inactive", "Under Maintenance")
THREAT_TYPES = (
    "IP Address", "Domain", "File Hash", "Malware Signature", "Other Indicators",
)
LOG_SEVERITIES = ("Information", "Warning", "Error", "Critical")
LOGIN_ACTIONS = {
    "successful": "LOGIN_SUCCESS",
    "failed": "LOGIN_FAILED",
    "blocked": "LOGIN_BLOCKED",
}


class ReportRepository:
    """Builds every report from the shared database."""

    def __init__(self, database_path=None):
        self.database_path = database_path

    # ---------- small helpers ----------

    def _scalar(self, db, sql, params=()):
        return db.execute(sql, params).fetchone()[0]

    def _count_by(self, db, table, column, known_values):
        """Count rows per value, listing every known value even when it is 0."""
        counts = {value: 0 for value in known_values}
        rows = db.execute(
            f"SELECT {column} AS value, COUNT(*) AS total "
            f"FROM {table} GROUP BY {column}"
        ).fetchall()
        for row in rows:
            value = row["value"] if row["value"] is not None else "Unknown"
            counts[value] = counts.get(value, 0) + row["total"]
        return counts

    def _recent_activities(self, db, limit):
        rows = db.execute(
            "SELECT log_id, timestamp, user_id, action, description, severity, "
            "related_service FROM audit_logs "
            "ORDER BY timestamp DESC, log_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 1. summary ----------

    def summary(self, limit):
        finished = ",".join("?" for _ in FINISHED_STATUSES)
        with get_db(self.database_path) as db:
            return {
                "users": self._scalar(db, "SELECT COUNT(*) FROM users"),
                "active_users": self._scalar(
                    db, "SELECT COUNT(*) FROM users WHERE account_status = 'Active'"
                ),
                "assets": self._scalar(db, "SELECT COUNT(*) FROM assets"),
                "critical_assets": self._scalar(
                    db, "SELECT COUNT(*) FROM assets WHERE criticality = 'Critical'"
                ),
                "incidents": self._scalar(db, "SELECT COUNT(*) FROM incidents"),
                "open_incidents": self._scalar(
                    db,
                    f"SELECT COUNT(*) FROM incidents WHERE status NOT IN ({finished})",
                    FINISHED_STATUSES,
                ),
                "incidents_by_severity": self._count_by(
                    db, "incidents", "severity", SEVERITIES
                ),
                "threats": self._scalar(db, "SELECT COUNT(*) FROM threats"),
                "critical_threats": self._scalar(
                    db, "SELECT COUNT(*) FROM threats WHERE severity = 'Critical'"
                ),
                "vulnerabilities": self._scalar(
                    db, "SELECT COUNT(*) FROM vulnerabilities"
                ),
                "open_vulnerabilities": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM vulnerabilities "
                    f"WHERE status NOT IN ({finished})",
                    FINISHED_STATUSES,
                ),
                "audit_records": self._scalar(db, "SELECT COUNT(*) FROM audit_logs"),
                "recent_activities": self._recent_activities(db, limit),
            }

    # ---------- 2. incidents ----------

    def incidents(self, limit):
        finished = ",".join("?" for _ in FINISHED_STATUSES)
        with get_db(self.database_path) as db:
            recent = db.execute(
                "SELECT incident_id, title, category, severity, status, "
                "reporter_id, assigned_analyst_id, created_at FROM incidents "
                "ORDER BY created_at DESC, incident_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return {
                "total_incidents": self._scalar(db, "SELECT COUNT(*) FROM incidents"),
                "open_incidents": self._scalar(
                    db,
                    f"SELECT COUNT(*) FROM incidents WHERE status NOT IN ({finished})",
                    FINISHED_STATUSES,
                ),
                "unassigned_open_incidents": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM incidents WHERE assigned_analyst_id IS NULL "
                    f"AND status NOT IN ({finished})",
                    FINISHED_STATUSES,
                ),
                "by_severity": self._count_by(db, "incidents", "severity", SEVERITIES),
                "by_status": self._count_by(db, "incidents", "status", INCIDENT_STATUSES),
                "recent_incidents": [dict(row) for row in recent],
            }

    # ---------- 3. assets ----------

    def assets(self, limit):
        with get_db(self.database_path) as db:
            critical = db.execute(
                "SELECT asset_id, asset_name, asset_type, ip_address, owner_id, "
                "department, status FROM assets WHERE criticality = 'Critical' "
                "ORDER BY asset_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return {
                "total_assets": self._scalar(db, "SELECT COUNT(*) FROM assets"),
                "critical_assets": self._scalar(
                    db, "SELECT COUNT(*) FROM assets WHERE criticality = 'Critical'"
                ),
                "by_type": self._count_by(db, "assets", "asset_type", ASSET_TYPES),
                "by_criticality": self._count_by(
                    db, "assets", "criticality", SEVERITIES
                ),
                "by_status": self._count_by(db, "assets", "status", ASSET_STATUSES),
                "critical_asset_list": [dict(row) for row in critical],
            }

    # ---------- 4. threats ----------

    def threats(self, limit):
        with get_db(self.database_path) as db:
            recent = db.execute(
                "SELECT threat_id, threat_type, threat_value, severity, source, "
                "date_added FROM threats "
                "ORDER BY date_added DESC, threat_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return {
                "total_threats": self._scalar(db, "SELECT COUNT(*) FROM threats"),
                "critical_threats": self._scalar(
                    db, "SELECT COUNT(*) FROM threats WHERE severity = 'Critical'"
                ),
                "by_severity": self._count_by(db, "threats", "severity", SEVERITIES),
                "by_type": self._count_by(db, "threats", "threat_type", THREAT_TYPES),
                "recent_threats": [dict(row) for row in recent],
            }

    # ---------- 5. vulnerabilities ----------

    def vulnerabilities(self, limit):
        finished = ",".join("?" for _ in FINISHED_STATUSES)
        with get_db(self.database_path) as db:
            critical = db.execute(
                "SELECT vulnerability_id, vulnerability_title, cve_identifier, "
                "cvss_score, affected_asset_id, status, created_at "
                "FROM vulnerabilities WHERE severity = 'Critical' "
                "ORDER BY cvss_score DESC, vulnerability_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            average = self._scalar(
                db, "SELECT ROUND(AVG(cvss_score), 1) FROM vulnerabilities"
            )
            return {
                "total_vulnerabilities": self._scalar(
                    db, "SELECT COUNT(*) FROM vulnerabilities"
                ),
                "open_vulnerabilities": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM vulnerabilities "
                    f"WHERE status NOT IN ({finished})",
                    FINISHED_STATUSES,
                ),
                "critical_vulnerabilities": self._scalar(
                    db,
                    "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'Critical'",
                ),
                "average_cvss_score": average,
                "by_severity": self._count_by(
                    db, "vulnerabilities", "severity", SEVERITIES
                ),
                "by_status": self._count_by(
                    db, "vulnerabilities", "status", VULNERABILITY_STATUSES
                ),
                "critical_vulnerability_list": [dict(row) for row in critical],
            }

    # ---------- 6. activity ----------

    def activity(self, limit):
        with get_db(self.database_path) as db:
            def action_count(action):
                return self._scalar(
                    db, "SELECT COUNT(*) FROM audit_logs WHERE action = ?", (action,)
                )

            successful = action_count(LOGIN_ACTIONS["successful"])
            failed = action_count(LOGIN_ACTIONS["failed"])
            blocked = action_count(LOGIN_ACTIONS["blocked"])
            top_actions = db.execute(
                "SELECT action, COUNT(*) AS count FROM audit_logs "
                "GROUP BY action ORDER BY count DESC, action ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return {
                "total_activities": self._scalar(db, "SELECT COUNT(*) FROM audit_logs"),
                "active_users": self._scalar(
                    db,
                    "SELECT COUNT(DISTINCT user_id) FROM audit_logs "
                    "WHERE user_id IS NOT NULL",
                ),
                "login_attempts": successful + failed + blocked,
                "successful_logins": successful,
                "failed_logins": failed,
                "blocked_logins": blocked,
                "permission_denied": action_count("PERMISSION_DENIED"),
                "by_severity": self._count_by(
                    db, "audit_logs", "severity", LOG_SEVERITIES
                ),
                "most_performed_actions": [dict(row) for row in top_actions],
                "recent_activities": self._recent_activities(db, limit),
            }
