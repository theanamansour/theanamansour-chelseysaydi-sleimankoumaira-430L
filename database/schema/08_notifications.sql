-- Service 8: Notification and Alert Management Service (Sleiman Koumaira)
-- Stores security notifications and alerts sent to users.

CREATE TABLE IF NOT EXISTS notifications (
    notification_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The user who receives the notification: a users.id from Service 1 (Users and Identity).
    -- Service 1 keeps its own database, so this cannot be a SQLite FOREIGN KEY; instead the
    -- API checks with Service 1 that the user exists (a logical foreign key).
    user_id           INTEGER NOT NULL,
    title             TEXT    NOT NULL,
    message           TEXT    NOT NULL,
    notification_type TEXT    NOT NULL
                      CHECK (notification_type IN ('Incident Assignment', 'Security Alert', 'System Notification',
                                                   'Threat Alert', 'Vulnerability Alert')),
    severity          TEXT    NOT NULL
                      CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT    NOT NULL DEFAULT 'Unread'
                      CHECK (status IN ('Unread', 'Read')),
    created_at        TEXT    NOT NULL DEFAULT (datetime('now')),  -- UTC
    read_at           TEXT,                                         -- UTC, set when marked as read

    -- An unread notification has no read date; a read one must have it.
    CHECK ((status = 'Unread' AND read_at IS NULL) OR (status = 'Read' AND read_at IS NOT NULL))
);

-- Makes "all notifications of one user" fast, the most common query.
CREATE INDEX IF NOT EXISTS notifications_by_user ON notifications (user_id);
