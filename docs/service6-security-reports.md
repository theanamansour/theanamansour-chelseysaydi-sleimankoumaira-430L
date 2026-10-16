# Service 6 API Documentation — Theana Mansour

Base URL: `http://127.0.0.1:5006/theana-mansour`

Service 6 builds read-only security reports for Security Administrators and Auditors.

## How the data is collected

All services store their records in the shared SQLite database
(`database/data/security_system.db`, set with `SYSTEM_DATABASE_PATH`). Service 6 reads
the tables each service owns. It only runs `SELECT` queries, so a report never changes
data.

| Report data | Table | Owner service |
|---|---|---|
| Users | `users` | Service 1 — Users and Identity Management |
| Assets | `assets` | Service 2 — Asset Management |
| Incidents | `incidents` | Service 3 — Incident Management |
| Threats | `threats` | Service 4 — Threat Intelligence |
| Activities and logins | `audit_logs` | Service 5 — Security Audit Logging |
| Vulnerabilities | `vulnerabilities` | Service 7 — Vulnerability Management |

Every request is checked through Service 1 (`POST /theana-mansour/auth/verify`). The
token is only accepted while its user still exists and is Active.

Every report generated, every missing token and every permission denial is also sent to
Service 5 as an audit event. These events are best effort: if Service 5 is down, the
report still works.

Run from the repository root:

```powershell
$env:INTERNAL_SERVICE_KEY = "same-value-as-service-5"
python -m services.reports.app
```

`python -m services.reports.sample_data` can optionally add clearly labelled sample
assets, incidents, threats and vulnerabilities for a local demo. It runs only once.

## Access

| Role | Access |
|---|---|
| Security Administrator | All six reports |
| Auditor | All six reports (read-only) |
| Security Analyst | None (`403`) |
| Regular Employee | None (`403`) |

## Common Request Details

- Method: `GET`
- Header: `Authorization: Bearer <token from Service 1 login>`
- Optional query parameter `limit` (whole number, 1–50, default 5) sets how many
  rows the "recent" and "critical" lists return. Any other query parameter is rejected.

## Response Format

```json
{
  "status": "success",
  "message": "Security summary report generated successfully",
  "report": "summary",
  "generated_at": "2026-10-16 12:00:00",
  "generated_by": { "user_id": 1, "username": "theanamansour", "role": "Security Administrator" },
  "data": { }
}
```

Every count list includes all allowed values, even when a value's count is 0, so reports
are easy to compare. "Open" means any status except `Resolved` and `Closed`.

## 1. Generate Security Summary Report

- Method/route: `GET /reports/summary`
- `data` fields:
  - users and assets: `users`, `active_users`, `assets`, `critical_assets`
  - incidents: `incidents`, `open_incidents`, `incidents_by_severity`
  - threats: `threats`, `critical_threats`
  - vulnerabilities: `vulnerabilities`, `open_vulnerabilities`
  - activity: `audit_records`, and `recent_activities` (the latest audit records)

## 2. Generate Incident Report

- Method/route: `GET /reports/incidents`
- `data` fields:
  - totals: `total_incidents`, `open_incidents`, `unassigned_open_incidents`
  - counts: `by_severity` (Low, Medium, High, Critical); `by_status` (Open, Under
    Investigation, Mitigated, Resolved, Closed)
  - list: `recent_incidents`

## 3. Generate Asset Report

- Method/route: `GET /reports/assets`
- `data` fields:
  - totals: `total_assets`, `critical_assets`
  - counts: `by_type` (the six asset types), `by_criticality`, `by_status`
  - list: `critical_asset_list`

## 4. Generate Threat Report

- Method/route: `GET /reports/threats`
- `data` fields:
  - totals: `total_threats`, `critical_threats`
  - counts: `by_severity`; `by_type` (IP Address, Domain, File Hash, Malware Signature,
    Other Indicators)
  - list: `recent_threats` (newest first)

## 5. Generate Vulnerability Report

- Method/route: `GET /reports/vulnerabilities`
- `data` fields:
  - totals: `total_vulnerabilities`, `open_vulnerabilities`,
    `critical_vulnerabilities`, `average_cvss_score`
  - counts: `by_severity`; `by_status` (Open, Under Investigation, In Progress,
    Resolved, Closed)
  - list: `critical_vulnerability_list` (highest CVSS first)

## 6. Generate Activity Report

- Method/route: `GET /reports/activity`
- `data` fields:
  - totals: `total_activities`, `active_users`
  - logins: `login_attempts`, `successful_logins`, `failed_logins`, `blocked_logins`
  - other: `permission_denied`
  - counts: `by_severity` (Information, Warning, Error, Critical)
  - lists: `most_performed_actions` (action and count, most frequent first) and
    `recent_activities`
- Login counts come from the audit records Service 1 sends to Service 5:
  - `LOGIN_SUCCESS` is a successful login
  - `LOGIN_FAILED` is a wrong username or password
  - `LOGIN_BLOCKED` is an Inactive or Suspended account trying to log in

## Errors

All errors use `{ "status": "error", "message": "..." }`:

- `400`: `Validation failed`, with an `errors` list, for an invalid `limit` or an unknown
  query parameter
- `401`: missing, invalid or expired token, or a user who was deleted or suspended
- `403`: `User does not have permission to perform this operation` (Security Analyst or
  Regular Employee)
- `404`: unknown URL
- `405`: wrong HTTP method (reports are `GET` only)
- `503`: `User service is unavailable` (Service 1 could not be reached to check the token)

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SYSTEM_DATABASE_PATH` | `database/data/security_system.db` | Shared database file |
| `USER_SERVICE_URL` | `http://127.0.0.1:5001/theana-mansour` | Service 1 address for token checks |
| `INTERNAL_SERVICE_KEY` | random key saved in the ignored `.internal_service_key` | Key for audit events sent to Service 5 |
| `AUDIT_LOG_URL` | `http://127.0.0.1:5005/chelsea-saydi/logs` | Service 5 address |
| `REPORTS_SERVICE_PORT` | `5006` | Port |
