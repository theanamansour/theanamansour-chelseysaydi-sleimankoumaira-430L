# Service 9 API Documentation — Chelsea Saydi

Base URL: `http://127.0.0.1:5009/chelsea-saydi`

Playbooks define a category, severity, and ordered incident-response actions. Protected
requests require `Authorization: Bearer <token>`.

## Endpoints

### Create Response Playbook
- Method/route: `POST /playbooks`
- Role: Security Administrator
- Body: `playbook_name`, `description`, `incident_category`, `severity`
- `created_by` is taken from the authenticated administrator
- Response: `201` with the stored playbook

### Retrieve All Playbooks
- Method/route: `GET /playbooks`
- Roles: Security Administrator, Security Analyst, Auditor
- Response: `200` with all playbook summaries

### Retrieve Specific Playbook
- Method/route: `GET /playbooks/{id}`
- Roles: Security Administrator, Security Analyst, Auditor
- Response: the playbook and its actions in step order
- Each action includes its complete status-change history

### Add Response Action
- Method/route: `POST /playbooks/{id}/actions`
- Roles: Security Administrator, Security Analyst
- Body: `action_description`, `step_number`
- Step numbers must be positive and unique inside a playbook
- New actions begin with `Pending` status

### Update Response Action Status
- Method/route: `PUT /actions/{id}/status`
- Roles: Security Administrator, Security Analyst
- Body: `status` and optional `assigned_user_id`
- Enforced lifecycle: `Pending → In Progress → Completed`
- Earlier steps must be completed before a later action can begin
- Completing an action automatically records its completion date
- Every status change is preserved in `response_action_history`

### Delete Playbook
- Method/route: `DELETE /playbooks/{id}`
- Role: Security Administrator
- Deleting a playbook also deletes its actions and action history

## Supported Values

Severity: `Low`, `Medium`, `High`, `Critical`.

Action status: `Pending`, `In Progress`, `Completed`.

## Common Errors

- `400`: malformed JSON, invalid severity/status, missing fields, or invalid transition
- `401`: missing, invalid, or expired token
- `403`: role does not permit the operation
- `404`: playbook or action does not exist
- `409`: duplicate step number or attempted execution before earlier steps
- `503`: User Service is unavailable for token verification
