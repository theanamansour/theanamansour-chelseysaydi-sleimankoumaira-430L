# Service 8 - Notification and Alert Management Service API (Sleiman Koumaira)

Base URL: `http://127.0.0.1:5008/sleiman-koumaira`
Every route includes the full name of the student who implemented it (`/sleiman-koumaira`).

**Authentication:** every endpoint needs the header `Authorization: Bearer <token>`. The token
comes from Service 1's login (`POST /theana-mansour/users/login`, Theana Mansour). For every
request this service sends the token to Service 1's `POST /theana-mansour/auth/verify`, which
checks the signature, the one-hour expiry and that the account is still Active, and returns the
user's ID, username and current role.

**Service-to-service:** other services create notifications (e.g. Threat Alerts from Service 4)
with the internal header `X-Service-Key: <key>` instead of a user token. The key comes from the
`INTERNAL_SERVICE_KEY` environment variable or a local file ignored by Git, never from the code.

**Who sees what**

| Role | Own notifications | Other users' notifications |
|---|---|---|
| Security Administrator | read, mark as read, delete | read, mark as read, search, create, delete |
| Auditor | read, search | read, search (read-only: cannot mark as read) |
| Security Analyst | read, mark as read, search | no (403) |
| Regular Employee | read, mark as read | no (403); cannot search |

**Allowed values**

| Field | Allowed values |
|---|---|
| `notification_type` | `Incident Assignment`, `Security Alert`, `System Notification`, `Threat Alert`, `Vulnerability Alert` |
| `severity` | `Low`, `Medium`, `High`, `Critical` |
| `status` | `Unread` (on creation), `Read` (after PUT /read) |

**Fields**

| Field | Type | Set by | Rule |
|---|---|---|---|
| `notification_id` | integer | database | Deleted IDs are never reused |
| `user_id` | integer | client | ID of an existing user in Service 1 (the recipient) |
| `title` | text | client | Required, max 150 characters |
| `message` | text | client | Required, max 1000 characters |
| `notification_type` | text | client | One of the types above |
| `severity` | text | client | One of the severities above |
| `status` | text | service | `Unread` on creation; `Read` after marking |
| `created_at` | text (UTC) | database | Date the notification was created |
| `read_at` | text (UTC) or null | service | Set the first time it is marked as read; never overwritten |

**Error format** (all endpoints):

```json
{"status": "error", "message": "...", "errors": ["only present for validation errors"]}
```

| Status | When |
|---|---|
| 400 | Validation failed (missing, empty, invalid or unknown fields; recipient does not exist; bad search criteria) |
| 401 | Missing token, or Service 1 rejected it (invalid, expired, or account not Active); the message comes from Service 1 |
| 403 | The role is not allowed, or the notification belongs to another user |
| 404 | No notification with this ID, or unknown URL |
| 405 | HTTP method not supported on this URL |
| 503 | Service 1 is unavailable, so the caller (or the recipient) cannot be checked |

The example responses below were captured from the running service.

---

## 1. Create Notification

| | |
|---|---|
| Purpose | Creates a notification for a user |
| Method | `POST` |
| Endpoint | `/sleiman-koumaira/notifications` |
| Allowed roles | Security Administrator, or another service with `X-Service-Key` |
| Required parameters | none in the URL |

**Request body** (all fields required; the status always starts as `Unread`):

```json
{
  "user_id": 4,
  "title": "Suspicious login detected",
  "message": "A login to your account was blocked from an unknown device.",
  "notification_type": "Security Alert",
  "severity": "Medium"
}
```

**Response - 201 Created**

```json
{
  "status": "success",
  "message": "Notification created successfully",
  "data": {
    "notification_id": 1,
    "user_id": 4,
    "title": "Suspicious login detected",
    "message": "A login to your account was blocked from an unknown device.",
    "notification_type": "Security Alert",
    "severity": "Medium",
    "status": "Unread",
    "created_at": "2026-10-13 20:00:11",
    "read_at": null
  }
}
```

**Possible errors:** 400, 401, 403, 503. Examples:

```json
HTTP 400
{
  "status": "error",
  "message": "Validation failed",
  "errors": [
    "notification_type must be one of: Incident Assignment, Security Alert, System Notification, Threat Alert, Vulnerability Alert"
  ]
}
```

```json
HTTP 400
{
  "status": "error",
  "message": "Validation failed",
  "errors": [
    "user_id 99999 does not match any registered user"
  ]
}
```

---

## 2. Retrieve User Notifications

| | |
|---|---|
| Purpose | Returns all notifications of one user, newest first |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/notifications/user/{user_id}` |
| Allowed roles | Security Administrator and Auditor (any user); Security Analyst and Regular Employee (own only) |
| Required parameters | `user_id` (path, integer) |
| Request body | none |

**Response - 200 OK**

```json
{
  "status": "success",
  "count": 2,
  "data": [
    {
      "notification_id": 2,
      "user_id": 4,
      "title": "Password policy updated",
      "message": "Passwords must now be changed every 90 days.",
      "notification_type": "System Notification",
      "severity": "Low",
      "status": "Unread",
      "created_at": "2026-10-13 20:00:11",
      "read_at": null
    },
    {
      "notification_id": 1,
      "user_id": 4,
      "title": "Suspicious login detected",
      "message": "A login to your account was blocked from an unknown device.",
      "notification_type": "Security Alert",
      "severity": "Medium",
      "status": "Unread",
      "created_at": "2026-10-13 20:00:11",
      "read_at": null
    }
  ]
}
```

A user without notifications gets an empty list (not an error):

```json
{
  "status": "success",
  "count": 0,
  "data": []
}
```

**Possible errors:** 401, 403. Example:

```json
HTTP 403
{
  "status": "error",
  "message": "You may only access your own notifications"
}
```

---

## 3. Retrieve Specific Notification

| | |
|---|---|
| Purpose | Returns one notification |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/notifications/{id}` |
| Allowed roles | Security Administrator and Auditor (any); Security Analyst and Regular Employee (own only) |
| Required parameters | `id` (path, integer) |
| Request body | none |

**Response - 200 OK**

```json
{
  "status": "success",
  "data": {
    "notification_id": 1,
    "user_id": 4,
    "title": "Suspicious login detected",
    "message": "A login to your account was blocked from an unknown device.",
    "notification_type": "Security Alert",
    "severity": "Medium",
    "status": "Unread",
    "created_at": "2026-10-13 20:00:11",
    "read_at": null
  }
}
```

**Possible errors:** 401, 403, 404. Example:

```json
HTTP 404
{
  "status": "error",
  "message": "Notification with ID 99999 not found"
}
```

---

## 4. Mark Notification as Read

| | |
|---|---|
| Purpose | Sets the status to `Read` and records the read date (UTC) |
| Method | `PUT` |
| Endpoint | `/sleiman-koumaira/notifications/{id}/read` |
| Allowed roles | Security Administrator (any); Security Analyst and Regular Employee (own only). Not the Auditor (read-only role) |
| Required parameters | `id` (path, integer) |
| Request body | none |

**Response - 200 OK**

```json
{
  "status": "success",
  "message": "Notification marked as read",
  "data": {
    "notification_id": 1,
    "user_id": 4,
    "title": "Suspicious login detected",
    "message": "A login to your account was blocked from an unknown device.",
    "notification_type": "Security Alert",
    "severity": "Medium",
    "status": "Read",
    "created_at": "2026-10-13 20:00:11",
    "read_at": "2026-10-13 20:00:11"
  }
}
```

Marking it again is allowed and keeps the first read date
(`"message": "Notification was already marked as read"`).

**Possible errors:** 401, 403, 404.

---

## 5. Search Notifications

| | |
|---|---|
| Purpose | Searches notifications; all criteria must match exactly (AND) |
| Method | `GET` |
| Endpoint | `/sleiman-koumaira/notifications/search` |
| Allowed roles | Security Administrator, Auditor (any user); Security Analyst (results limited to own notifications) |
| Required parameters | at least one query parameter (below) |
| Request body | none |

| Query parameter | Match |
|---|---|
| `user_id` | exact (positive whole number) |
| `notification_type` | exact (one of the allowed types) |
| `severity` | exact (one of the allowed severities) |
| `status` | exact (`Unread` or `Read`) |

Example: `GET /sleiman-koumaira/notifications/search?user_id=4&status=Read`

**Response - 200 OK**

```json
{
  "status": "success",
  "count": 1,
  "data": [
    {
      "notification_id": 1,
      "user_id": 4,
      "title": "Suspicious login detected",
      "message": "A login to your account was blocked from an unknown device.",
      "notification_type": "Security Alert",
      "severity": "Medium",
      "status": "Read",
      "created_at": "2026-10-13 20:00:11",
      "read_at": "2026-10-13 20:00:11"
    }
  ]
}
```

**Possible errors:** 400 (no criteria, unknown parameter, invalid value), 401, 403 (an analyst asking
for another user's notifications, or a Regular Employee).

---

## 6. Delete Notification

| | |
|---|---|
| Purpose | Removes a notification |
| Method | `DELETE` |
| Endpoint | `/sleiman-koumaira/notifications/{id}` |
| Allowed roles | Security Administrator |
| Required parameters | `id` (path, integer) |
| Request body | none |

**Response - 200 OK**

```json
{
  "status": "success",
  "message": "Notification 2 deleted successfully"
}
```

**Possible errors:** 401, 403, 404.

---

## When notifications are generated

| Notification type | Generated by | Status |
|---|---|---|
| Threat Alert | **Service 4 automatically**, when a High or Critical threat is added: one notification for every Active Security Administrator and Security Analyst (recipients read from Service 1) | Implemented |
| Incident Assignment | Service 3 (Incident Management), when an incident is assigned to an analyst | Contract ready: `POST /sleiman-koumaira/notifications` with `X-Service-Key` |
| Vulnerability Alert | Service 7 (Vulnerability Management), e.g. for High/Critical vulnerabilities | Contract ready (same call) |
| Security Alert, System Notification | A Security Administrator, or any service, for security events and important system events | Implemented (same call) |

Service-to-service request used by other services:

```
POST http://127.0.0.1:5008/sleiman-koumaira/notifications
X-Service-Key: <INTERNAL_SERVICE_KEY>
Content-Type: application/json

{"user_id": 2, "title": "...", "message": "...", "notification_type": "Incident Assignment", "severity": "High"}
```

## Database

Table `notifications` in the team's shared SQLite database (`database/data/security_system.db`):
`notification_id` (primary key), `user_id`, `title`, `message`, `notification_type` (CHECK),
`severity` (CHECK), `status` (CHECK, default `Unread`), `created_at` (default current UTC time),
`read_at`, plus a CHECK that an unread notification has no read date and a read one has one,
and an index on `user_id` for fast "notifications of one user" queries.

`user_id` is a **foreign key** to `users(id)` (Service 1's table in the same database). When a
Security Administrator creates a notification, the service also asks Service 1
(`GET /theana-mansour/users`) whether the user exists, so a wrong ID gets a clear 400 message.
Other services (internal key) are not asked about; for them the foreign key stops an unknown
`user_id`, which also returns 400.

## Automatic audit logging

Sent to the Security Audit Logging Service (Service 5) with the internal `X-Service-Key` header.
Until Service 5 is running the service prints `Audit service unreachable, log not saved` and continues.

| Event | `action` | `severity` |
|---|---|---|
| Notification created | `CREATE_NOTIFICATION` | Information |
| Notification marked as read | `MARK_NOTIFICATION_READ` | Information |
| Notification deleted | `DELETE_NOTIFICATION` | Warning |
| Request without a valid token (401) | `UNAUTHENTICATED_ACCESS` | Warning |
| Role not allowed, or another user's notification (403) | `PERMISSION_DENIED` | Warning |
