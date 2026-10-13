-- Service 4: Threat Intelligence Service (Sleiman Koumaira)
-- Stores known threat indicators: malicious IPs, domains, file hashes, malware signatures.

CREATE TABLE IF NOT EXISTS threats (
    threat_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type  TEXT    NOT NULL
                 CHECK (threat_type IN ('IP Address', 'Domain', 'File Hash', 'Malware Signature', 'Other Indicators')),
    threat_value TEXT    NOT NULL,
    description  TEXT    NOT NULL,
    severity     TEXT    NOT NULL
                 CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    source       TEXT    NOT NULL,
    date_added   TEXT    NOT NULL DEFAULT (datetime('now')),  -- UTC, e.g. 2026-10-13 17:05:12

    -- The same indicator cannot be stored twice (same type AND same value).
    UNIQUE (threat_type, threat_value)
);
