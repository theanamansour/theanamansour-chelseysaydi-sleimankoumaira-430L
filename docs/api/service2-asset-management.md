# Service 2 - Asset Management Service API (Sleiman Koumaira)

Base URL: `http://127.0.0.1:5002/sleiman-koumaira`
Every route includes the full name of the student who implemented it (`/sleiman-koumaira`).

**Authentication:** every endpoint needs the header `Authorization: Bearer <token>`. The token
comes from Service 1's login (`POST /theana-mansour/users/login`, Theana Mansour). For every
request this service sends the token to Service 1's `POST /theana-mansour/auth/verify`, which
checks the signature, the one-hour expiry and that the account is still Active, and returns the
user's ID, username and current role. The role is then compared with the allowed roles below.

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
| `owner_id` | integer | yes | yes | Positive whole number, and must be the ID of an existing user in Service 1 |
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
| 401 | Missing token, or Service 1 rejected it (invalid, expired, or account not Active); the message comes from Service 1 |
| 403 | Valid token, but the role is not allowed to call this endpoint |
| 503 | Service 1 is unavailable, so the caller (or the owner) cannot be checked |

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

**Possible errors:** 400, 401, 403, 503. Example (all problems are reported together):

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

**Possible errors:** 401, 403, 404.

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

**Possible errors:** 400 (no criteria, unknown parameter, invalid type or criticality), 401, 403.

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

**Possible errors:** 400, 401, 403, 404, 503.

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

**Possible errors:** 401, 403, 404 (no asset with this ID).

---

## Relationships and integration points

| Relationship (assignment) | How it is handled |
|---|---|
| Each asset has one owner; one user owns many assets | `owner_id` stores the owner's user ID from Service 1. Each service has its own SQLite database, so this is a **logical foreign key**: before saving (POST, or PUT that changes the owner) the service calls Service 1's `GET /theana-mansour/users` with the administrator's token and rejects an ID that does not exist (400). |
| Department | Stored as text on the asset (the assignment defines no departments table). |
| Related incidents (Service 3) | `incidents.asset_id` will hold an `asset_id` from this service. |
| Related vulnerabilities (Service 7) | `vulnerabilities.affected_asset_id` will hold an `asset_id` from this service. |

## Automatic audit logging

Every data change and every rejected access attempt is sent to the Security Audit Logging
Service (Service 5) with the internal `X-Service-Key` header. Until Service 5 is running the
service prints `Audit service unreachable, log not saved` and continues.

| Event | `action` | `severity` |
|---|---|---|
| Asset added | `CREATE_ASSET` | Information |
| Asset updated (old -> new values) | `UPDATE_ASSET` | Information |
| Asset deleted | `DELETE_ASSET` | Warning |
| Request without a valid token (401) | `UNAUTHENTICATED_ACCESS` | Warning |
| Role not allowed (403) | `PERMISSION_DENIED` | Warning |

Still to agree with the team: what happens when an asset that incidents or vulnerabilities
still refer to is deleted (those services keep their own databases).
