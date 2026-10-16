# Security Incident Detection and Response Management System

Backend project for AUB's Software Tools Lab (430L), Sprint I.

The system helps organizations report, investigate, and respond to cybersecurity
incidents. It is organized as nine independent REST services that exchange data
through API calls. The backend uses role-based access control, persistent database
storage, validation, consistent JSON errors, and security audit logging.

## Team

- Theana Mansour
- Chelsea Saydi
- Sleiman Koumaira

## System Services

1. **Users and Identity Management** — accounts, authentication, roles, and account
   status.
2. **Asset Management** — organizational servers, workstations, applications,
   databases, network devices, and cloud resources.
3. **Incident Management** — incident reporting, analyst assignment, investigation
   notes, and lifecycle tracking.
4. **Threat Intelligence** — malicious indicators such as IP addresses, domains,
   hashes, and malware signatures.
5. **Security Audit Logging** — immutable records of authentication, authorization,
   and data modification events.
6. **Security Reports** — summaries and statistics collected from the other services.
7. **Vulnerability Management** — CVEs, CVSS scores, affected assets, and remediation
   progress.
8. **Notification and Alert Management** — user alerts, delivery history, and read
   status.
9. **Security Playbook and Response Automation** — ordered response procedures and
   action progress.

Each service is designed to run independently:

- Service 1: port `5001`
- Service 2: port `5002`
- Service 3: port `5003`
- Service 4: port `5004`
- Service 5: port `5005`
- Service 6: port `5006`
- Service 7: port `5007`
- Service 8: port `5008`
- Service 9: port `5009`

## Roles and Access Control

The platform supports four roles:

- **Security Administrator** — manages users and security records and can perform
  privileged operations.
- **Security Analyst** — investigates assigned incidents and works with security data.
- **Regular Employee** — manages a personal account, reports incidents, and views
  personal notifications.
- **Auditor** — has read-only access to permitted records and reports.

Protected requests must include the bearer token returned by Service 1:

```text
Authorization: Bearer <token>
```

Requests with missing authentication return `401`. Authenticated users without the
required role or resource ownership return `403`. Permission violations are sent to
the Audit Logging Service.

## Architecture

Clients such as Postman call the REST services over HTTP. Service 1 authenticates the
caller and verifies tokens. Domain services validate related records through API calls;
for example, Incident Management validates reporters through Service 1 and affected
assets through Service 2. Security-relevant operations are forwarded to Service 5.

SQLite is used for local Sprint I persistence. SQL statements use bound parameters to
prevent SQL injection, while API validation and database constraints reject malformed
or unsupported values.

## Repository Layout

```text
services/       Service source code
tests/          Automated API and database tests
docs/           API documentation
postman/        Importable Postman collections
requirements.txt
```

Development for individual services is kept in feature branches before integration
into `main`.

## Local Setup

Python 3.11 or newer is recommended.

```bash
git clone https://github.com/theanamansour/theanamansour-chelseysaydi-sleimankoumaira-430L.git
cd theanamansour-chelseysaydi-sleimankoumaira-430L
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Never commit generated database files, virtual environments, API tokens, or secret
keys.

## Service 3: Incident Management

This branch contains Service 3, implemented by Chelsea Saydi. It provides:

- `POST /chelsea-saydi/incidents` — create an incident
- `GET /chelsea-saydi/incidents` — retrieve all incidents
- `GET /chelsea-saydi/incidents/{id}` — retrieve a specific incident
- `PUT /chelsea-saydi/incidents/{id}/assign` — assign a security analyst
- `PUT /chelsea-saydi/incidents/{id}/status` — advance incident status
- `POST /chelsea-saydi/incidents/{id}/notes` — add an investigation note

Supported severity levels are `Low`, `Medium`, `High`, and `Critical`.

The enforced lifecycle is:

```text
Open → Under Investigation → Mitigated → Resolved → Closed
```

Skipped, reversed, or post-closure transitions are rejected. Closing an incident
automatically records its resolution date.

Start Service 1 and Service 2 first, then run Service 3 from the repository root:

```bash
python -m services.incidents.app
```

Service 3 listens on `http://127.0.0.1:5003`. Its peer-service locations can be
configured with:

- `USER_SERVICE_URL`
- `ASSET_SERVICE_URL`
- `AUDIT_SERVICE_URL`
- `INTERNAL_SERVICE_KEY`
- `INCIDENT_SERVICE_PORT`

Detailed Service 3 request formats and errors are documented in
`docs/service3-incident-management.md`. An importable collection is available at
`postman/Chelsea_Saydi_Service3.postman_collection.json`.

## Service 5: Security Audit Logging

Service 5 is implemented by Chelsea Saydi. It stores immutable security events and
provides:

- `POST /chelsea-saydi/logs` — create a security log
- `GET /chelsea-saydi/logs` — retrieve all logs
- `GET /chelsea-saydi/logs/{id}` — retrieve a specific log
- `GET /chelsea-saydi/logs/search` — filter logs
- `DELETE /chelsea-saydi/logs/{id}` — delete a log as an administrator
- `GET /chelsea-saydi/logs/user/{user_id}` — retrieve one user's activity

Start Service 1 for authentication, then run:

```bash
python -m services.audit_logs.app
```

Service 5 listens on `http://127.0.0.1:5005`. Trusted services authenticate log
creation with `X-Service-Key`; administrators may instead use a bearer token. Configure
the shared secret with `INTERNAL_SERVICE_KEY`.

Detailed documentation is available at
`docs/service5-security-audit-logging.md`. The Postman collection is
`postman/Chelsea_Saydi_Service5.postman_collection.json`.

## Testing

Run the automated test suite from the repository root:

```bash
python -m pytest -q
```

Tests use temporary databases and mocked peer services, so test runs do not alter
demonstration data. Postman should be used for final execution evidence and screenshots
against the running services.

## API Response Format

Successful responses use:

```json
{
  "status": "success",
  "message": "Operation completed successfully",
  "data": {}
}
```

Errors use:

```json
{
  "status": "error",
  "message": "Validation failed",
  "errors": ["A clear explanation of the invalid input"]
}
```

## Project Evidence

The final submission must include actual Postman execution screenshots, database
records, a database schema diagram, API documentation, GitHub contribution history,
and a report explaining each team member's work. Any AI assistance must be disclosed
in the final report as required by the assignment.
