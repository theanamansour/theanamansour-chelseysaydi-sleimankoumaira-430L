"""
Service 2 - Asset Management Service (Sleiman Koumaira)

The Asset model: what one asset record looks like, plus the rules about its fields.
"""
from dataclasses import asdict, dataclass

ASSET_TYPES = ("Server", "Workstation", "Database", "Application", "Network Device", "Cloud Resource")
CRITICALITY_LEVELS = ("Low", "Medium", "High", "Critical")
ASSET_STATUSES = ("Active", "Inactive", "Under Maintenance")
DEFAULT_STATUS = "Active"

# Fields the client must send in POST /assets.
REQUIRED_FIELDS = ("asset_name", "asset_type", "ip_address", "department", "owner_id", "criticality")
# Fields the client may also send in POST /assets.
OPTIONAL_FIELDS = ("operating_system", "location", "status")
# Fields PUT /assets/{id} may change (the ones listed in the assignment).
UPDATABLE_FIELDS = ("asset_name", "owner_id", "department", "criticality", "status")
# Query parameters GET /assets/search accepts.
SEARCH_FIELDS = ("asset_name", "asset_type", "ip_address", "department", "criticality")


@dataclass
class Asset:
    asset_id: int
    asset_name: str
    asset_type: str
    ip_address: str
    operating_system: str | None
    owner_id: int
    department: str
    location: str | None
    criticality: str
    status: str

    @classmethod
    def from_row(cls, row):
        """Build an Asset object from one row of the assets table."""
        return cls(
            asset_id=row["asset_id"],
            asset_name=row["asset_name"],
            asset_type=row["asset_type"],
            ip_address=row["ip_address"],
            operating_system=row["operating_system"],
            owner_id=row["owner_id"],
            department=row["department"],
            location=row["location"],
            criticality=row["criticality"],
            status=row["status"],
        )

    def to_dict(self):
        """Convert to a dictionary so Flask can send it as JSON."""
        return asdict(self)
