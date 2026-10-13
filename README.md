# Security Incident Detection and Response Management System

## Service 3: Incident Management (Chelsea Saydi)

This branch implements the complete Incident Management Service required by Sprint I.
It stores incidents and investigation notes in SQLite, validates the incident lifecycle,
checks roles through Service 1, validates affected assets through Service 2, and sends
security activity events to Service 5 when it is available.

### Setup and run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m services.incidents.app
```

The service runs at `http://127.0.0.1:5003`. Every route includes the student's full
name as required: `/chelsea-saydi/...`.

Service 1 must run on port 5001 and Service 2 on port 5002 for real API calls. Obtain
a bearer token from Service 1's login endpoint and send it in every request:

```text
Authorization: Bearer <token>
```

Environment variables can override peer-service locations:

- `USER_SERVICE_URL`
- `ASSET_SERVICE_URL`
- `AUDIT_SERVICE_URL`
- `INTERNAL_SERVICE_KEY`
- `INCIDENT_SERVICE_PORT`

### Tests

```bash
python -m pytest -q
```

Tests use isolated temporary databases and mocked peer services, so they do not alter
demonstration data.
