"""
Service 8 - Notification and Alert Management Service (Sleiman Koumaira)

All SQL for the notifications table lives here. Every query uses "?" placeholders, so user
input is sent to SQLite separately from the SQL text (this prevents SQL injection).
"""
from database.connection import get_db  # the team's shared database (foreign keys on)
from services.notifications.models import SEARCH_FIELDS, Notification

# Largest number SQLite can store in an INTEGER column.
MAX_SQLITE_INTEGER = 2**63 - 1

# Newest notifications first, like an inbox.
NEWEST_FIRST = "ORDER BY notification_id DESC"


class NotificationRepository:
    """Reads and writes rows of the notifications table."""

    def __init__(self, database_path):
        self.database_path = database_path

    def create(self, data):
        """INSERT a new notification (status Unread, no read date) and return it."""
        with get_db(self.database_path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO notifications (user_id, title, message, notification_type, severity)
                VALUES (?, ?, ?, ?, ?)
                """,
                (data["user_id"], data["title"], data["message"], data["notification_type"], data["severity"]),
            )
            new_id = cursor.lastrowid
        return self.get_by_id(new_id)

    def get_by_id(self, notification_id):
        """Return the Notification, or None if no row has this ID."""
        if notification_id > MAX_SQLITE_INTEGER:
            return None
        with get_db(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM notifications WHERE notification_id = ?", (notification_id,)
            ).fetchone()
        return Notification.from_row(row) if row else None

    def get_for_user(self, user_id):
        """All notifications received by one user (may be an empty list)."""
        if user_id > MAX_SQLITE_INTEGER:
            return []
        with get_db(self.database_path) as connection:
            rows = connection.execute(
                f"SELECT * FROM notifications WHERE user_id = ? {NEWEST_FIRST}", (user_id,)
            ).fetchall()
        return [Notification.from_row(row) for row in rows]

    def search(self, criteria):
        """
        criteria is a dict such as {"user_id": 2, "status": "Unread"}.
        Every criterion must match exactly, and all of them must match (AND).
        """
        # Column names come from our own list, never from the user.
        fields = [field for field in SEARCH_FIELDS if field in criteria]
        where = " AND ".join(f"{field} = ?" for field in fields)
        with get_db(self.database_path) as connection:
            rows = connection.execute(
                f"SELECT * FROM notifications WHERE {where} {NEWEST_FIRST}",
                [criteria[field] for field in fields],
            ).fetchall()
        return [Notification.from_row(row) for row in rows]

    def mark_as_read(self, notification_id):
        """
        Set status to Read and record the read date (UTC), only if it is still Unread,
        so the first read date is never overwritten. Returns the notification.
        """
        with get_db(self.database_path) as connection:
            connection.execute(
                """
                UPDATE notifications
                SET status = 'Read', read_at = datetime('now')
                WHERE notification_id = ? AND status = 'Unread'
                """,
                (notification_id,),
            )
        return self.get_by_id(notification_id)

    def delete(self, notification_id):
        """DELETE the row. Returns True if a row was deleted."""
        if notification_id > MAX_SQLITE_INTEGER:
            return False
        with get_db(self.database_path) as connection:
            cursor = connection.execute("DELETE FROM notifications WHERE notification_id = ?", (notification_id,))
            return cursor.rowcount > 0
