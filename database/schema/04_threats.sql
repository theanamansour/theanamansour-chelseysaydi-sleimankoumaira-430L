-- Service 4: Threat Intelligence Service (Sleiman Koumaira)

CREATE TABLE IF NOT EXISTS threats (
    threat_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type  TEXT NOT NULL CHECK(threat_type IN (
                     'IP Address', 'Domain', 'File Hash',
                     'Malware Signature', 'Other Indicators'
                 )),
    threat_value TEXT NOT NULL,
    description  TEXT NOT NULL,
    severity     TEXT NOT NULL
                 CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    source       TEXT NOT NULL,
    date_added   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(threat_type, threat_value)
);
