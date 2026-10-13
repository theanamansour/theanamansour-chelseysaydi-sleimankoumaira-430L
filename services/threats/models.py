"""
Service 4 - Threat Intelligence Service (Sleiman Koumaira)

The Threat model: what one threat record looks like, plus the rules about its fields.
"""
from dataclasses import asdict, dataclass

THREAT_TYPES = ("IP Address", "Domain", "File Hash", "Malware Signature", "Other Indicators")
SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")

# Fields the client must send in POST /threats.
REQUIRED_FIELDS = ("threat_type", "threat_value", "description", "severity", "source")
# Fields PUT /threats/{id} may change. Type and value are the threat's identity, so they are fixed.
UPDATABLE_FIELDS = ("description", "severity", "source")
# Query parameters GET /threats/search accepts.
SEARCH_FIELDS = ("threat_type", "threat_value", "severity", "source")


@dataclass
class Threat:
    threat_id: int
    threat_type: str
    threat_value: str
    description: str
    severity: str
    source: str
    date_added: str

    @classmethod
    def from_row(cls, row):
        """Build a Threat object from one row of the threats table."""
        return cls(
            threat_id=row["threat_id"],
            threat_type=row["threat_type"],
            threat_value=row["threat_value"],
            description=row["description"],
            severity=row["severity"],
            source=row["source"],
            date_added=row["date_added"],
        )

    def to_dict(self):
        """Convert to a dictionary so Flask can send it as JSON."""
        return asdict(self)
