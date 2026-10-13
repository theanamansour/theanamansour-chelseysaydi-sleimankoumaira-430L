# Service 4 - Threat Intelligence Service API (Sleiman Koumaira)

Base URL: `http://127.0.0.1:5004/sleiman-koumaira`
Every route includes the full name of the student who implemented it (`/sleiman-koumaira`).

**Authentication:** every endpoint needs the header `Authorization: Bearer <token>`. The token
comes from Service 1's login (`POST /theana-mansour/users/login`, Theana Mansour). For every
request this service sends the token to Service 1's `POST /theana-mansour/auth/verify`, which
checks the signature, the one-hour expiry and that the account is still Active, and returns the
user's ID, username and current role. The role is then compared with the allowed roles below.

**Allowed values**

| Field | Allowed values |
|---|---|
| `threat_type` | `IP Address`, `Domain`, `File Hash`, `Malware Signature`, `Other Indicators` |
| `severity` | `Low`, `Medium`, `High`, `Critical` |

**Value format rules** (checked by `threat_type`):

| Type | Rule | Example |
|---|---|---|
| IP Address | valid IPv4 or IPv6 address | `203.0.113.45` |
| Domain | labels of letters/digits/hyphens separated by dots, ending in a letters-only extension | `secure-bank-login.example` |
| File Hash | hexadecimal; 32 (MD5), 40 (SHA-1) or 64 (SHA-256) characters | `44d88612fea8a8f36de82e1278abb02f` |
| Malware Signature, Other Indicators | any text up to 255 characters | `Trojan.GenericKD.4614` |

Domains and hashes are stored in lowercase and IP addresses in standard form, so the same
indicator written differently is still detected as a duplicate.

**Error format** (all endpoints):

```json
{"status": "error", "message": "...", "errors": ["only present for validation errors"]}
```

| Status | When |
|---|---|
| 400 | Validation failed (missing, empty, invalid, unknown or non-updatable fields; bad search criteria) |
| 401 | Missing token, or Service 1 rejected it (invalid, expired, or account not Active); the message comes from Service 1 |
| 403 | Valid token, but the role is not allowed to call this endpoint |
| 404 | No threat with this ID, or unknown URL |
| 405 | HTTP method not supported on this URL |
| 409 | A threat with the same type and value already exists |
| 503 | Service 1 (authentication) is unavailable, so the caller cannot be identified |

The example responses below were captured from the running service.

---

## 1. Add Threat Indicator

| | |
|---|---|
| Purpose | Adds a new threat indicator |
| Method | `POST` |
| Endpoint | `/sleiman-koumaira/threats` |
| Allowed roles | Security Administrator |
| Required parameters | none in the URL; Authorization header |

**Request body** (all fields required):

```json
{
  "threat_type": "IP Address",
  "threat_value": "203.0.113.45",
  "description": "Command-and-control server of a botnet",
  "severity": "High",
  "source": "AbuseIPDB"
}
```

**Response - 201 Created** (for High and Critical threats the message also says how many threat
alerts were sent, e.g. `"Threat indicator added successfully; threat alert sent to 3 user(s)"`)

```json
{
  "status": "success",
  "message": "Threat indicator added successfully",
  "data": {
    "threat_id": 1,
    "threat_type": "IP Address",
    "threat_value": "203.0.113.45",
    "description": "Command-and-control server of a botnet",
    "severity": "High",
    "source": "AbuseIPDB",
    "date_added": "2026-10-13 17:25:11"
  }
}
```

**Possible errors:** 400, 401, 403, 409. Examples:

```json
HTTP 400
{
  "status": "error",
  "message": "Validation failed",
  "errors": [
    "'999.10.10.10' is not a valid IPv4 or IPv6 address",
    "severity must be one of: Low, Medium, High, Critical"
  ]
}
```

```json
HTTP 409
{
  "status": "error",
  "message": "Duplicate threat indicator: this IP Address is already stored with ID 1"
}
```

---

## 2. Retrieve All Threat Indicators

| | |
|---|---|
| Purpose | Returns every stored threat with its information, severity, source and date added |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/threats` |
| Allowed roles | Security Administrator, Security Analyst, Auditor |
| Required parameters | Authorization header |
| Request body | none |

**Response - 200 OK** (`count` is the number of threats; `data` is empty when there are none)

```json
{
  "status": "success",
  "count": 2,
  "data": [
    {
      "threat_id": 1,
      "threat_type": "IP Address",
      "threat_value": "203.0.113.45",
      "description": "Command-and-control server of a botnet",
      "severity": "High",
      "source": "AbuseIPDB",
      "date_added": "2026-10-13 17:25:11"
    },
    {
      "threat_id": 2,
      "threat_type": "Domain",
      "threat_value": "secure-bank-login.example",
      "description": "Phishing site copying a bank login page",
      "severity": "Critical",
      "source": "PhishTank",
      "date_added": "2026-10-13 17:25:11"
    }
  ]
}
```

**Possible errors:** 401, 403. Example:

```json
HTTP 403
{
  "status": "error",
  "message": "User does not have permission to perform this operation"
}
```

---

## 3. Retrieve Specific Threat Indicator

| | |
|---|---|
| Purpose | Returns the complete information of one threat |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/threats/{id}` |
| Allowed roles | Security Administrator, Security Analyst, Auditor |
| Required parameters | `id` (path, integer); Authorization header |
| Request body | none |

**Response - 200 OK**

```json
{
  "status": "success",
  "data": {
    "threat_id": 1,
    "threat_type": "IP Address",
    "threat_value": "203.0.113.45",
    "description": "Command-and-control server of a botnet",
    "severity": "High",
    "source": "AbuseIPDB",
    "date_added": "2026-10-13 17:25:11"
  }
}
```

**Possible errors:** 401, 403, 404. Example:

```json
HTTP 404
{
  "status": "error",
  "message": "Threat indicator with ID 99999 not found"
}
```

---

## 4. Search Threat Indicators

| | |
|---|---|
| Purpose | Searches threat records; all given criteria must match (AND) |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/threats/search` |
| Allowed roles | Security Administrator, Security Analyst, Auditor |
| Required parameters | at least one query parameter (below); Authorization header |
| Request body | none |

| Query parameter | Match |
|---|---|
| `threat_type` | exact (one of the allowed types) |
| `severity` | exact (one of the allowed levels) |
| `threat_value` | contains the text, ignoring upper/lower case |
| `source` | contains the text, ignoring upper/lower case |

Example: `GET /sleiman-koumaira/threats/search?severity=Critical`

**Response - 200 OK**

```json
{
  "status": "success",
  "count": 1,
  "data": [
    {
      "threat_id": 2,
      "threat_type": "Domain",
      "threat_value": "secure-bank-login.example",
      "description": "Phishing site copying a bank login page",
      "severity": "Critical",
      "source": "PhishTank",
      "date_added": "2026-10-13 17:25:11"
    }
  ]
}
```

**Possible errors:** 400 (no criteria, unknown parameter, invalid type or severity), 401, 403. Example:

```json
HTTP 400
{
  "status": "error",
  "message": "Invalid search criteria",
  "errors": [
    "Provide at least one search parameter: threat_type, threat_value, severity, source"
  ]
}
```

---

## 5. Update Threat Information

| | |
|---|---|
| Purpose | Updates the description, severity and/or source of a threat |
| Method | `PUT` |
| Endpoint | `/sleiman-koumaira/threats/{id}` |
| Allowed roles | Security Administrator |
| Required parameters | `id` (path, integer); Authorization header |

**Request body** (one or more fields; `threat_type` and `threat_value` cannot be changed):

```json
{
  "severity": "Critical",
  "source": "CERT"
}
```

**Response - 200 OK**

```json
{
  "status": "success",
  "message": "Threat information updated successfully",
  "data": {
    "threat_id": 1,
    "threat_type": "IP Address",
    "threat_value": "203.0.113.45",
    "description": "Command-and-control server of a botnet",
    "severity": "Critical",
    "source": "CERT",
    "date_added": "2026-10-13 17:25:11"
  }
}
```

**Possible errors:** 400, 401, 403, 404. Example:

```json
HTTP 400
{
  "status": "error",
  "message": "Validation failed",
  "errors": [
    "These fields cannot be updated: threat_value. Allowed fields: description, severity, source"
  ]
}
```

---

## 6. Delete Threat Indicator

| | |
|---|---|
| Purpose | Removes a threat record |
| Method | `DELETE` |
| Endpoint | `/sleiman-koumaira/threats/{id}` |
| Allowed roles | Security Administrator |
| Required parameters | `id` (path, integer); Authorization header |
| Request body | none |

**Response - 200 OK**

```json
{
  "status": "success",
  "message": "Threat indicator 2 deleted successfully"
}
```

**Possible errors:** 401, 403, 404. Example:

```json
HTTP 401
{
  "status": "error",
  "message": "Authentication required: send 'Authorization: Bearer <token>'"
}
```

---

## Automatic threat alerts (Service 8)

When a **High** or **Critical** threat is added, the service:

1. asks Service 1 for the user list (`GET /theana-mansour/users`, using the administrator's token),
2. keeps every **Active** Security Administrator and Security Analyst,
3. creates one `Threat Alert` notification for each of them in Service 8
   (`POST /sleiman-koumaira/notifications` with the internal `X-Service-Key` header).

The notification's severity is the threat's severity. If Service 1 or Service 8 is unavailable the
threat is still saved and the message reports how many alerts were sent.

## Automatic audit logging

Every data change and every rejected access attempt is sent to the Security Audit Logging
Service (Service 5) with the internal `X-Service-Key` header (its value comes from an environment
variable or a local file that Git ignores, never from the code). Until Service 5 is running the
service prints `Audit service unreachable, log not saved` and continues:

| Event | `action` | `severity` |
|---|---|---|
| Threat added | `CREATE_THREAT` | Information |
| Threat updated (old -> new values) | `UPDATE_THREAT` | Information |
| Threat deleted | `DELETE_THREAT` | Warning |
| Request without a valid token (401) | `UNAUTHENTICATED_ACCESS` | Warning |
| Role not allowed (403) | `PERMISSION_DENIED` | Warning |
