# Service 5 API Documentation — Chelsea Saydi

Base URL: `http://127.0.0.1:5005/chelsea-saydi`

Audit logs are immutable: there is no update API, and a database trigger rejects direct
SQL updates. All queries use bound parameters. Protected requests require
`Authorization: Bearer <token>`.

## Endpoints

### Create Log Record
- Method/route: `POST /logs`
- Access: Security Administrator or a trusted service using `X-Service-Key`
- Body: `user_id`, `action`, `description`, `severity`, `related_service`
- `user_id` may be `null` when the caller is unknown, such as a failed login
- Severity: `Information`, `Warning`, `Error`, or `Critical`
- Response: `201` with the stored log and timestamp

### Retrieve All Logs
- Method/route: `GET /logs`
- Roles: Security Administrator, Auditor
- Response: `200` with newest records first and a result count

### Retrieve Specific Log
- Method/route: `GET /logs/{id}`
- Roles: Security Administrator, Security Analyst, Auditor
- Response: `200` with the complete record, or `404`

### Search Logs
- Method/route: `GET /logs/search`
- Roles: Security Administrator, Security Analyst, Auditor
- Query parameters: `user_id`, `date`, `action`, `severity`, `related_service`
- Dates use `YYYY-MM-DD`
- Multiple filters are combined with `AND`
- `action` and `related_service` support case-insensitive partial matching

### Delete Log
- Method/route: `DELETE /logs/{id}`
- Role: Security Administrator
- A successful deletion creates a new `AUDIT_LOG_DELETED` warning record, preserving
  accountability for the administrative action

### Retrieve Logs By User
- Method/route: `GET /logs/user/{user_id}`
- Roles: Security Administrator, Auditor
- Response: all records for the user, or an empty array when none exist

## Automatically Recorded Events

The service records missing-token and permission-denied attempts against its own routes.
Other services submit authentication, user, incident, asset, threat, permission, and
data-modification events through the internal service-key API.

## Common Errors

- `400`: malformed JSON, invalid fields, severity, date, or ID
- `401`: missing, invalid, or expired token
- `403`: authenticated user lacks the required role
- `404`: requested log does not exist
- `503`: User Service is unavailable for token verification
