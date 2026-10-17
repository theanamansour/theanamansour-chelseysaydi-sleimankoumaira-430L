"""
Service 8 - Notification and Alert Management Service (Sleiman Koumaira)

The Notification model: what one notification looks like, plus the rules about its fields.
"""
from dataclasses import asdict, dataclass

NOTIFICATION_TYPES = ("Incident Assignment", "Security Alert", "System Notification", "Threat Alert",
                      "Vulnerability Alert")
SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")
STATUSES = ("Unread", "Read")

# Fields the client must send in POST /notifications. The status always starts as Unread.
REQUIRED_FIELDS = ("user_id", "title", "message", "notification_type", "severity")
# Query parameters GET /notifications/search accepts.
SEARCH_FIELDS = ("user_id", "notification_type", "severity", "status")


@dataclass
class Notification:
    notification_id: int
    user_id: int
    title: str
    message: str
    notification_type: str
    severity: str
    status: str
    created_at: str
    read_at: str | None

    @classmethod
    def from_row(cls, row):
        """Build a Notification object from one row of the notifications table."""
        return cls(
            notification_id=row["notification_id"],
            user_id=row["user_id"],
            title=row["title"],
            message=row["message"],
            notification_type=row["notification_type"],
            severity=row["severity"],
            status=row["status"],
            created_at=row["created_at"],
            read_at=row["read_at"],
        )

    def to_dict(self):
        """Convert to a dictionary so Flask can send it as JSON."""
        return asdict(self)
