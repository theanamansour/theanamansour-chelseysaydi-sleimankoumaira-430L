# Service 2 - Asset Management Service API (Sleiman Koumaira)

Base URL: `http://127.0.0.1:5002/sleiman-koumaira`
Every route includes the full name of the student who implemented it (`/sleiman-koumaira`).

**Authentication and role permissions:** the allowed roles are listed for every endpoint.
They are enforced once Service 1's shared token verification is integrated (agreed with
the Service 1 owner). Until then the endpoints accept requests without a token, and no
unauthorized-access evidence is produced for this service.

**Allowed values**

| Field | Allowed values |
|---|---|
| `asset_type` | `Server`, `Workstation`, `Database`, `Application`, `Network Device`, `Cloud Resource` |
| `criticality` | `Low`, `Medium`, `High`, `Critical` |
| `status` | `Active`, `Inactive`, `Under Maintenance` (default `Active`) |

**Fields**

| Field | Type | Required on POST | Updatable (PUT) | Rule |
|---|---|---|---|---|
| `asset_id` | integer | generated | no | Assigned by the database; deleted IDs are never reused |
| `asset_name` | text | yes | yes | Not blank, max 100 characters |
| `asset_type` | text | yes | no | One of the asset types above |
| `ip_address` | text | yes | no | Valid IPv4 or IPv6 address, stored in standard form |
| `operating_system` | text or null | no | no | Max 100 characters ("if applicable") |
| `owner_id` | integer | yes | yes | Positive whole number: the owner's user ID in Service 1 |
| `department` | text | yes | yes | Not blank, max 100 characters |
| `location` | text or null | no | no | Max 100 characters |
| `criticality` | text | yes | yes | One of the criticality levels above |
| `status` | text | no | yes | One of the statuses above |

**Error format** (all endpoints):

```json
{"status": "error", "message": "...", "errors": ["only present for validation errors"]}
```

| Status | When |
|---|---|
| 400 | Validation failed (missing, empty, invalid, unknown or non-updatable fields; bad search criteria) |
| 404 | No asset with this ID, or unknown URL |
| 405 | HTTP method not supported on this URL |
| 401 / 403 | Added with Service 1 integration: missing/invalid token, or role not allowed |

The example responses below were captured from the running service.

---

## 1. Add New Asset

| | |
|---|---|
| Purpose | Adds a new organizational asset |
| Method | `POST` |
| Endpoint | `/sleiman-koumaira/assets` |
| Allowed roles | Security Administrator |
| Required parameters | none in the URL |

**Request body:**

```json
{
  "asset_name": "Main Web Server",
  "asset_type": "Server",
  "ip_address": "192.0.2.10",
  "operating_system": "Ubuntu 22.04",
  "owner_id": 1,
  "department": "IT",
  "location": "Beirut Data Center",
  "criticality": "Critical"
}
```

**Response - 201 Created** (`status` defaulted to `Active`)

```json
{
  "status": "success",
  "message": "Asset added successfully",
  "data": {
    "asset_id": 1,
    "asset_name": "Main Web Server",
    "asset_type": "Server",
    "ip_address": "192.0.2.10",
    "operating_system": "Ubuntu 22.04",
    "owner_id": 1,
    "department": "IT",
    "location": "Beirut Data Center",
    "criticality": "Critical",
    "status": "Active"
  }
}
```

**Possible errors:** 400. Example (all problems are reported together):

```json
HTTP 400
{
  "status": "error",
  "message": "Validation failed",
  "errors": [
    "asset_type must be one of: Server, Workstation, Database, Application, Network Device, Cloud Resource",
    "'999.1.1.1' is not a valid IPv4 or IPv6 address",
    "criticality must be one of: Low, Medium, High, Critical"
  ]
}
```

---

## 2. Retrieve All Assets

| | |
|---|---|
| Purpose | Returns every asset with its details, criticality level and current status |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/assets` |
| Allowed roles | Security Administrator, Auditor |
| Required parameters | none |
| Request body | none |

**Response - 200 OK** (`count` is the number of assets; `data` is empty when there are none)

```json
{
  "status": "success",
  "count": 2,
  "data": [
    {
      "asset_id": 1,
      "asset_name": "Main Web Server",
      "asset_type": "Server",
      "ip_address": "192.0.2.10",
      "operating_system": "Ubuntu 22.04",
      "owner_id": 1,
      "department": "IT",
      "location": "Beirut Data Center",
      "criticality": "Critical",
      "status": "Active"
    },
    {
      "asset_id": 2,
      "asset_name": "Payroll Application",
      "asset_type": "Application",
      "ip_address": "198.51.100.35",
      "operating_system": null,
      "owner_id": 2,
      "department": "Finance",
      "location": null,
      "criticality": "High",
      "status": "Active"
    }
  ]
}
```

---

## 3. Retrieve Specific Asset

| | |
|---|---|
| Purpose | Returns the complete information of one asset |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/assets/{id}` |
| Allowed roles | Security Administrator, Security Analyst, Auditor |
| Required parameters | `id` (path, integer) |
| Request body | none |

**Response - 200 OK**

```json
{
  "status": "success",
  "data": {
    "asset_id": 1,
    "asset_name": "Main Web Server",
    "asset_type": "Server",
    "ip_address": "192.0.2.10",
    "operating_system": "Ubuntu 22.04",
    "owner_id": 1,
    "department": "IT",
    "location": "Beirut Data Center",
    "criticality": "Critical",
    "status": "Active"
  }
}
```

**Possible errors:** 404.

```json
HTTP 404
{
  "status": "error",
  "message": "Asset with ID 99999 not found"
}
```

---

## 4. Search Assets

| | |
|---|---|
| Purpose | Searches assets; all given criteria must match (AND) |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/assets/search` |
| Allowed roles | Security Administrator, Security Analyst, Auditor |
| Required parameters | at least one query parameter (below) |
| Request body | none |

| Query parameter | Match |
|---|---|
| `asset_type` | exact (one of the allowed types) |
| `criticality` | exact (one of the allowed levels) |
| `asset_name` | contains the text, ignoring upper/lower case |
| `ip_address` | contains the text (e.g. a subnet such as `192.0.2.`) |
| `department` | contains the text, ignoring upper/lower case |

Example: `GET /sleiman-koumaira/assets/search?department=finance`

**Response - 200 OK**

```json
{
  "status": "success",
  "count": 1,
  "data": [
    {
      "asset_id": 2,
      "asset_name": "Payroll Application",
      "asset_type": "Application",
      "ip_address": "198.51.100.35",
      "operating_system": null,
      "owner_id": 2,
      "department": "Finance",
      "location": null,
      "criticality": "High",
      "status": "Active"
    }
  ]
}
```

**Possible errors:** 400 (no criteria, unknown parameter, invalid type or criticality).

```json
HTTP 400
{
  "status": "error",
  "message": "Invalid search criteria",
  "errors": [
    "Provide at least one search parameter: asset_name, asset_type, ip_address, department, criticality"
  ]
}
```

---

## 5. Update Asset Information

| | |
|---|---|
| Purpose | Updates the name, owner, department, criticality and/or status of an asset |
| Method | `PUT` |
| Endpoint | `/sleiman-koumaira/assets/{id}` |
| Allowed roles | Security Administrator |
| Required parameters | `id` (path, integer) |

**Request body** (one or more of `asset_name`, `owner_id`, `department`, `criticality`, `status`):

```json
{
  "criticality": "High",
  "status": "Under Maintenance"
}
```

**Response - 200 OK**

```json
{
  "status": "success",
  "message": "Asset information updated successfully",
  "data": {
    "asset_id": 1,
    "asset_name": "Main Web Server",
    "asset_type": "Server",
    "ip_address": "192.0.2.10",
    "operating_system": "Ubuntu 22.04",
    "owner_id": 1,
    "department": "IT",
    "location": "Beirut Data Center",
    "criticality": "High",
    "status": "Under Maintenance"
  }
}
```

**Possible errors:** 400, 404.

```json
HTTP 400
{
  "status": "error",
  "message": "Validation failed",
  "errors": [
    "These fields cannot be updated: ip_address. Allowed fields: asset_name, owner_id, department, criticality, status"
  ]
}
```

---

## 6. Delete Asset

| | |
|---|---|
| Purpose | Removes an asset from the system |
| Method | `DELETE` |
| Endpoint | `/sleiman-koumaira/assets/{id}` |
| Allowed roles | Security Administrator |
| Required parameters | `id` (path, integer) |
| Request body | none |

**Response - 200 OK**

```json
{
  "status": "success",
  "message": "Asset 2 deleted successfully"
}
```

**Possible errors:** 404 (no asset with this ID).

---

## Relationships and integration points

| Relationship (assignment) | How it is handled |
|---|---|
| Each asset has one owner; one user owns many assets | `owner_id` stores the owner's user ID. The `FOREIGN KEY (owner_id) REFERENCES users(user_id)` is added when Service 1's users table is connected. |
| Department | Stored as text on the asset (the assignment defines no departments table). |
| Related incidents (Service 3) | `incidents.asset_id` will reference `assets.asset_id`. |
| Related vulnerabilities (Service 7) | `vulnerabilities.affected_asset_id` will reference `assets.asset_id`. |

Still to connect with the team (not simulated in this service):

- Role checks (401/403) through Service 1's token verification.
- Automatic audit logs to Service 5 for asset changes and permission violations.
- What happens when an asset that still has incidents or vulnerabilities is deleted.
