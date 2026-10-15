-- Service 7: Vulnerability Management Service (Theana Mansour)

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_title TEXT NOT NULL
                        CHECK(length(trim(vulnerability_title)) BETWEEN 1 AND 150),
    description         TEXT NOT NULL CHECK(length(trim(description)) BETWEEN 1 AND 2000),
    cve_identifier      TEXT NOT NULL COLLATE NOCASE,
    cvss_score          REAL NOT NULL CHECK(cvss_score BETWEEN 0.0 AND 10.0),
    severity            TEXT NOT NULL
                        CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    affected_asset_id   INTEGER NOT NULL,
    discovery_source    TEXT NOT NULL
                        CHECK(length(trim(discovery_source)) BETWEEN 1 AND 150),
    status              TEXT NOT NULL DEFAULT 'Open'
                        CHECK(status IN (
                            'Open', 'Under Investigation', 'In Progress',
                            'Resolved', 'Closed'
                        )),
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolution_date     TEXT,
    FOREIGN KEY(affected_asset_id) REFERENCES assets(asset_id),
    UNIQUE(cve_identifier, affected_asset_id)
);

CREATE INDEX IF NOT EXISTS vulnerabilities_asset
    ON vulnerabilities(affected_asset_id);
CREATE INDEX IF NOT EXISTS vulnerabilities_severity
    ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS vulnerabilities_status
    ON vulnerabilities(status);
