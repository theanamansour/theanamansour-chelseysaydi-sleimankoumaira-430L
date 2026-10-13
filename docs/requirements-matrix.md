# Sprint 1 Service and Route Matrix

The project has nine services and fifty four required REST endpoints.

## Theana Mansour

### Service 1 Users and Identity Management

- `POST /users/register`
- `POST /users/login`
- `PUT /users/{id}`
- `DELETE /users/{id}`
- `GET /users`
- `GET /users/{username}`

### Service 6 Security Reports

- `GET /reports/summary`
- `GET /reports/incidents`
- `GET /reports/assets`
- `GET /reports/threats`
- `GET /reports/vulnerabilities`
- `GET /reports/activity`

### Service 8 Notification and Alert Management

- `POST /notifications`
- `GET /notifications/user/{user_id}`
- `GET /notifications/{id}`
- `PUT /notifications/{id}/read`
- `GET /notifications/search`
- `DELETE /notifications/{id}`

## Chelsey Saydi

### Service 2 Asset Management

- `POST /assets`
- `PUT /assets/{id}`
- `DELETE /assets/{id}`
- `GET /assets`
- `GET /assets/{id}`
- `GET /assets/search`

### Service 4 Threat Intelligence

- `POST /threats`
- `GET /threats`
- `GET /threats/{id}`
- `GET /threats/search`
- `PUT /threats/{id}`
- `DELETE /threats/{id}`

### Service 7 Vulnerability Management

- `POST /vulnerabilities`
- `GET /vulnerabilities`
- `GET /vulnerabilities/{id}`
- `PUT /vulnerabilities/{id}`
- `GET /vulnerabilities/search`
- `DELETE /vulnerabilities/{id}`

## Sleiman Koumaira

### Service 3 Incident Management

- `POST /incidents`
- `GET /incidents`
- `GET /incidents/{id}`
- `PUT /incidents/{id}/assign`
- `PUT /incidents/{id}/status`
- `POST /incidents/{id}/notes`

### Service 5 Security Audit Logging

- `POST /logs`
- `GET /logs`
- `GET /logs/{id}`
- `GET /logs/search`
- `DELETE /logs/{id}`
- `GET /logs/user/{user_id}`

### Service 9 Security Playbook and Response Automation

- `POST /playbooks`
- `GET /playbooks`
- `GET /playbooks/{id}`
- `POST /playbooks/{id}/actions`
- `PUT /actions/{id}/status`
- `DELETE /playbooks/{id}`

## Cross cutting requirements

- Roles: Security Administrator, Security Analyst, Regular Employee/User, and Auditor.
- Authentication is required for protected operations.
- Inactive and suspended users cannot authenticate.
- Every protected operation must check the caller's role and permission.
- Unauthorized operations must be rejected and logged.
- Passwords must be hashed and never stored as plain text.
- Validation and sanitization apply to all services.
- Error responses must be clear and consistent.
- Audit logs preserve the original record and cannot be edited after creation.
- The report service uses actual data from the relevant services or tables.
- All APIs must be documented and included in the Postman collection.

