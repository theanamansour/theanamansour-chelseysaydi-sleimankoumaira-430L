-- Service 8: Notification and Alert Management Service (Sleiman Koumaira)

CREATE TABLE IF NOT EXISTS notifications (
    notification_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL,
    title             TEXT NOT NULL,
    message           TEXT NOT NULL,
    notification_type TEXT NOT NULL CHECK(notification_type IN (
                          'Incident Assignment', 'Security Alert',
                          'System Notification', 'Threat Alert',
                          'Vulnerability Alert'
                      )),
    severity          TEXT NOT NULL
                      CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT NOT NULL DEFAULT 'Unread'
                      CHECK(status IN ('Unread', 'Read')),
    created_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    read_at           TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id),
    CHECK(
        (status = 'Unread' AND read_at IS NULL)
        OR (status = 'Read' AND read_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS notifications_by_user ON notifications(user_id);
