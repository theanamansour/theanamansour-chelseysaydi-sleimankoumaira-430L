-- Service 3: Incident Management Service (Chelsea Saydi)

CREATE TABLE IF NOT EXISTS incidents (
    incident_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title               TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 150),
    description         TEXT NOT NULL CHECK(length(trim(description)) BETWEEN 1 AND 2000),
    category            TEXT NOT NULL CHECK(length(trim(category)) BETWEEN 1 AND 100),
    severity            TEXT NOT NULL
                        CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    reporter_id         INTEGER NOT NULL,
    asset_id            INTEGER NOT NULL,
    assigned_analyst_id INTEGER,
    status               TEXT NOT NULL DEFAULT 'Open'
                         CHECK(status IN (
                             'Open', 'Under Investigation', 'Mitigated',
                             'Resolved', 'Closed'
                         )),
    created_at           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolution_date      TEXT,
    FOREIGN KEY(reporter_id) REFERENCES users(id),
    FOREIGN KEY(asset_id) REFERENCES assets(asset_id),
    FOREIGN KEY(assigned_analyst_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL,
    analyst_id   INTEGER NOT NULL,
    note_content TEXT NOT NULL CHECK(length(trim(note_content)) BETWEEN 1 AND 2000),
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY(analyst_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS incidents_reporter ON incidents(reporter_id);
CREATE INDEX IF NOT EXISTS incidents_asset ON incidents(asset_id);
CREATE INDEX IF NOT EXISTS incidents_assigned_analyst ON incidents(assigned_analyst_id);
CREATE INDEX IF NOT EXISTS notes_incident ON investigation_notes(incident_id);
