"""Insert clearly labelled sample records so the reports have data to show.

Optional, for local demos only. It adds assets, incidents, threats and
vulnerabilities owned by the first Security Administrator in the shared
database. Every row is marked "Sample" so it is easy to recognise, and running
the script again does nothing once the sample rows exist.

Prefer creating records through each team member's own service when it is
running; this script only fills the gaps while those services are being built.

Run from the project root (after creating an administrator with
python -m services.users.create_admin):
    python -m services.reports.sample_data
"""
from database.config import get_database_path
from database.connection import get_db
from database.init_db import init_database

SAMPLE_SOURCE = "Sample data"

ASSETS = (
    ("Sample - Main Web Server", "Server", "10.0.0.10", "Ubuntu 24.04", "IT", "Critical", "Active"),
    ("Sample - Finance Laptop", "Workstation", "10.0.1.21", "Windows 11", "Finance", "Medium", "Active"),
    ("Sample - Customer Database", "Database", "10.0.0.30", "PostgreSQL 16", "IT", "Critical", "Active"),
    ("Sample - HR Portal", "Application", "10.0.0.40", None, "HR", "High", "Under Maintenance"),
    ("Sample - Core Router", "Network Device", "10.0.0.1", None, "IT", "High", "Active"),
    ("Sample - Backup Bucket", "Cloud Resource", "52.10.4.8", None, "IT", "Low", "Inactive"),
)

# (title, category, severity, status, asset index)
INCIDENTS = (
    ("Sample - Phishing email reported", "Phishing", "Medium", "Open", 1),
    ("Sample - Malware on web server", "Malware", "Critical", "Under Investigation", 0),
    ("Sample - Brute force on portal", "Unauthorized Access", "High", "Mitigated", 3),
    ("Sample - Suspicious DB query", "Data Breach", "Critical", "Open", 2),
    ("Sample - Router config change", "Policy Violation", "Low", "Resolved", 4),
    ("Sample - Leaked backup link", "Data Exposure", "High", "Closed", 5),
)

# (type, value, description, severity)
THREATS = (
    ("IP Address", "203.0.113.45", "Repeated SSH brute-force source", "High"),
    ("IP Address", "198.51.100.7", "Known command-and-control server", "Critical"),
    ("Domain", "login-update-portal.example", "Credential phishing domain", "Critical"),
    ("Domain", "cdn-fastfiles.example", "Malware download site", "Medium"),
    ("File Hash", "44d88612fea8a8f36de82e1278abb02f", "Test malware sample hash", "High"),
    ("Malware Signature", "Trojan.Sample.Agent", "Remote access trojan family", "Critical"),
    ("Other Indicators", "User-Agent: EvilBot/1.0", "Scanner user agent", "Low"),
)

# (title, description, cve, cvss, severity, asset index, status)
VULNERABILITIES = (
    ("Sample - OpenSSH remote code execution", "Outdated OpenSSH on web server",
     "CVE-2024-6387", 8.1, "High", 0, "Open"),
    ("Sample - Log4Shell", "Vulnerable logging library in HR portal",
     "CVE-2021-44228", 10.0, "Critical", 3, "In Progress"),
    ("Sample - Weak TLS configuration", "TLS 1.0 still enabled on router",
     "CVE-2011-3389", 5.9, "Medium", 4, "Under Investigation"),
    ("Sample - Database privilege escalation", "Unpatched database server",
     "CVE-2023-5869", 8.8, "High", 2, "Resolved"),
    ("Sample - Windows SMB flaw", "Missing patch on finance laptop",
     "CVE-2020-0796", 10.0, "Critical", 1, "Open"),
    ("Sample - Open bucket listing", "Public listing on backup bucket",
     "CVE-2019-0001", 3.1, "Low", 5, "Closed"),
)


def load_sample_data(database_path=None):
    """Insert the sample rows once. Returns a short status message."""
    path = database_path or get_database_path()
    init_database(database_path=path)
    with get_db(path) as db:
        if db.execute(
            "SELECT 1 FROM threats WHERE source = ? LIMIT 1", (SAMPLE_SOURCE,)
        ).fetchone():
            return "Sample data is already loaded; nothing was changed."

        admin = db.execute(
            "SELECT id FROM users WHERE role = 'Security Administrator' "
            "AND account_status = 'Active' ORDER BY id LIMIT 1"
        ).fetchone()
        if admin is None:
            return ("No active Security Administrator found. Create one first with: "
                    "python -m services.users.create_admin")
        owner = admin["id"]

        asset_ids = []
        for name, kind, ip, system, department, criticality, status in ASSETS:
            cursor = db.execute(
                "INSERT INTO assets (asset_name, asset_type, ip_address, "
                "operating_system, owner_id, department, location, criticality, status) "
                "VALUES (?, ?, ?, ?, ?, ?, 'Beirut HQ', ?, ?)",
                (name, kind, ip, system, owner, department, criticality, status),
            )
            asset_ids.append(cursor.lastrowid)

        for title, category, severity, status, asset in INCIDENTS:
            resolved = "CURRENT_TIMESTAMP" if status == "Closed" else "NULL"
            db.execute(
                "INSERT INTO incidents (title, description, category, severity, "
                f"reporter_id, asset_id, status, resolution_date) "
                f"VALUES (?, ?, ?, ?, ?, ?, ?, {resolved})",
                (title, f"{title} (sample record)", category, severity,
                 owner, asset_ids[asset], status),
            )

        for kind, value, description, severity in THREATS:
            db.execute(
                "INSERT INTO threats (threat_type, threat_value, description, "
                "severity, source) VALUES (?, ?, ?, ?, ?)",
                (kind, value, description, severity, SAMPLE_SOURCE),
            )

        for title, description, cve, cvss, severity, asset, status in VULNERABILITIES:
            resolved = "CURRENT_TIMESTAMP" if status in ("Resolved", "Closed") else "NULL"
            db.execute(
                "INSERT INTO vulnerabilities (vulnerability_title, description, "
                "cve_identifier, cvss_score, severity, affected_asset_id, "
                f"discovery_source, status, resolution_date) "
                f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, {resolved})",
                (title, description, cve, cvss, severity, asset_ids[asset],
                 SAMPLE_SOURCE, status),
            )

    return (f"Inserted {len(ASSETS)} assets, {len(INCIDENTS)} incidents, "
            f"{len(THREATS)} threats and {len(VULNERABILITIES)} vulnerabilities "
            f"into {path}.")


if __name__ == "__main__":
    print(load_sample_data())
