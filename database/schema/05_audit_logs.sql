-- Service 5: Security Audit Logging Service (Chelsea Saydi)

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER,
    action          TEXT NOT NULL CHECK(length(trim(action)) BETWEEN 1 AND 100),
    description     TEXT NOT NULL CHECK(length(trim(description)) BETWEEN 1 AND 1000),
    timestamp       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity        TEXT NOT NULL
                    CHECK(severity IN ('Information', 'Warning', 'Error', 'Critical')),
    related_service TEXT NOT NULL CHECK(length(trim(related_service)) BETWEEN 1 AND 100),
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS audit_logs_action ON audit_logs(action);

CREATE TRIGGER IF NOT EXISTS audit_logs_are_immutable
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'Audit logs cannot be modified');
END;
