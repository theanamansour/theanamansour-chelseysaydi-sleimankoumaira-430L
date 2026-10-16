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

## Shared Database

All services use one SQLite file, `database/data/security_system.db`. You can
override it with `SYSTEM_DATABASE_PATH`. The generated `.db` file is never committed;
the SQL files in `database/schema/` define the tables. Create or update every table
from the repository root:

```bash
python -m database.init_db
```

Open connections with `database.connection.get_db`, which turns on
`PRAGMA foreign_keys = ON`. See `database/README.md` for details.

## Service 1: Users and Identity Management

Service 1 is implemented by Theana Mansour. It provides:

- `POST /theana-mansour/users/register` — register a user
- `POST /theana-mansour/users/login` — log in and receive a one-hour token
- `PUT /theana-mansour/users/{id}` — update name, email or department
- `DELETE /theana-mansour/users/{id}` — delete a user (administrator)
- `GET /theana-mansour/users` — retrieve all users
- `GET /theana-mansour/users/{username}` — retrieve one user
- `PUT /theana-mansour/users/{id}/role` and `/status` — administrator role and
  account-status changes
- `POST /theana-mansour/auth/verify` — token check used by the other services

Create the first administrator, then start the service:

```bash
python -m services.users.create_admin
python -m services.users.app
```

Service 1 listens on `http://127.0.0.1:5001`. Start Service 1 and Service 5 with the
same `INTERNAL_SERVICE_KEY` so Service 5 accepts Service 1's audit events. Detailed
documentation is in `docs/service1-users-identity.md`. Its Postman requests and test
cases are in `postman/Theana_Mansour_Service1.postman_collection.json`.

## Service 6: Security Reports

Service 6 is implemented by Theana Mansour. It builds read-only reports from the shared
database for Security Administrators and Auditors:

- `GET /theana-mansour/reports/summary` — overall security status
- `GET /theana-mansour/reports/incidents` — incidents by severity and status
- `GET /theana-mansour/reports/assets` — assets by type, critical assets
- `GET /theana-mansour/reports/threats` — threats by severity and type, recent threats
- `GET /theana-mansour/reports/vulnerabilities` — vulnerabilities by severity and status
- `GET /theana-mansour/reports/activity` — logins, failed logins, most performed actions

Start Service 1 first (tokens are checked through it), then run:

```bash
python -m services.reports.app
```

Service 6 listens on `http://127.0.0.1:5006`. Optional demo data:
`python -m services.reports.sample_data`. Detailed documentation is in
`docs/service6-security-reports.md`. Its Postman requests and test cases are in the
collection `postman/Theana_Mansour_Service6.postman_collection.json`.

## Service 7: Vulnerability Management

Service 7 is implemented by Theana Mansour. It tracks vulnerabilities found on assets:

- `POST /theana-mansour/vulnerabilities` — add a vulnerability (administrator)
- `GET /theana-mansour/vulnerabilities` — retrieve all vulnerabilities
- `GET /theana-mansour/vulnerabilities/{id}` — retrieve one vulnerability
- `PUT /theana-mansour/vulnerabilities/{id}` — update details and advance the status
- `GET /theana-mansour/vulnerabilities/search` — search by CVE, severity, status or asset
- `DELETE /theana-mansour/vulnerabilities/{id}` — delete a vulnerability (administrator)

The enforced lifecycle is:

```text
Open → Under Investigation → In Progress → Resolved → Closed
```

The severity must match the CVSS score (Low 0.0–3.9, Medium 4.0–6.9, High 7.0–8.9,
Critical 9.0–10.0). High and Critical vulnerabilities send a Vulnerability Alert
through Service 8.

Start Service 1 first, then run:

```bash
python -m services.vulnerabilities.app
```

Service 7 listens on `http://127.0.0.1:5007`. Detailed documentation is in
`docs/service7-vulnerability-management.md`. Its Postman requests and test cases are in
`postman/Theana_Mansour_Service7.postman_collection.json`.

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
