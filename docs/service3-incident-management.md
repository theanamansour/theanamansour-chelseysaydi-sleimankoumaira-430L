# Service 3 API Documentation — Chelsea Saydi

Base URL: `http://127.0.0.1:5003/chelsea-saydi`

All endpoints require `Authorization: Bearer <token>`. Success responses use
`{"status":"success","data":...}` and errors use
`{"status":"error","message":"...","errors":[...]}`.

## Endpoints

### Create Incident
- Method/route: `POST /incidents`
- Roles: Security Administrator, Regular Employee
- Body: `title`, `description`, `category`, `severity`, `reporter_id`, `asset_id`
- Severity: `Low`, `Medium`, `High`, or `Critical`
- Response: `201` with the stored incident
- Validation: employees can only use their own user ID; the asset must exist in
  the shared `assets` table

### Retrieve All Incidents
- Method/route: `GET /incidents`
- Roles: Security Administrator, Auditor
- Response: `200` with an array and `count`

### Retrieve Specific Incident
- Method/route: `GET /incidents/{id}`
- Roles: all roles
- Access scope: employees see incidents they reported; analysts see assigned incidents;
  administrators and auditors can see every incident
- Response: the incident and all associated investigation notes, or `404`

### Assign Incident to Analyst
- Method/route: `PUT /incidents/{id}/assign`
- Role: Security Administrator
- Body: `{"analyst_id": 2}`
- Validation: Service 1 must confirm the user has the Security Analyst role
- Side effects: generates an `INCIDENT_ASSIGNED` audit event and sends the analyst an
  `Incident Assignment` notification through Service 8

### Update Incident Status
- Method/route: `PUT /incidents/{id}/status`
- Roles: Security Administrator, assigned Security Analyst
- Body: `{"status": "Under Investigation"}`
- Enforced lifecycle:
  `Open → Under Investigation → Mitigated → Resolved → Closed`
- Closing an incident records its resolution date; skipped/reversed transitions return `400`

### Add Investigation Note
- Method/route: `POST /incidents/{id}/notes`
- Roles: Security Administrator, assigned Security Analyst
- Body: `{"note_content": "Evidence collected and attachment isolated."}`
- Response: `201` with note ID, incident ID, author ID, content, and timestamp

## Common errors

- `400`: malformed JSON, missing/unknown fields, invalid severity or transition
- `401`: missing, invalid, or expired authentication token
- `403`: authenticated role or resource ownership is insufficient
- `404`: incident does not exist
- `503`: the User service is unavailable

SQL statements use bound parameters. The database also has `CHECK` and foreign-key
constraints as a second validation layer.
