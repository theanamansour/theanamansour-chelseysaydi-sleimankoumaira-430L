# Security Incident Detection and Response Management System Backend

Sprint 1 repository for Theana Mansour, Chelsey Saydi, and Sleiman Koumaira.

## Required repository name

The Sprint 1 assignment requires the project name:

`TheanaMansour-ChelseySaydi-SleimanKoumaira-430L`

The current GitHub repository name does not yet include `-430L`. Rename it before the final Moodle submission.

## Service ownership

| Student | Assigned services |
|---|---|
| Theana Mansour | 1 Users and Identity, 6 Security Reports, 8 Notifications and Alerts |
| Chelsey Saydi | 2 Assets, 4 Threat Intelligence, 7 Vulnerabilities |
| Sleiman Koumaira | 3 Incidents, 5 Security Audit Logging, 9 Playbooks and Response Automation |

The detailed route matrix is in [docs/requirements-matrix.md](docs/requirements-matrix.md). Moodle deliverables and evidence rules are in [docs/evidence-checklist.md](docs/evidence-checklist.md).

## Intended repository structure

```text
services/
  users-identity/
  assets/
  incidents/
  threats/
  audit-logs/
  reports/
  vulnerabilities/
  notifications/
  playbooks/
shared/
database/
postman/
docs/
```

Each service must be independently runnable and expose the exact assignment endpoints. Cross-service data should be obtained by API calls. The database design must still show the primary keys, foreign keys, and relationships required by the assignment.

## Contribution rules

- Every student implements only their three assigned services.
- Every student commits and pushes using their own GitHub account.
- Use focused, meaningful commits throughout development.
- Open a pull request from each student's branch.
- Merge without squashing so the original author commits remain visible.
- Never manufacture screenshots, execution results, database records, Postman responses, or GitHub activity.
- Disclose AI assistance in the final report, including where it was used and why.

Suggested branches:

- `student/theana-users-reports-notifications`
- `student/chelsey-assets-threats-vulnerabilities`
- `student/sleiman-incidents-audit-playbooks`

## Evidence rule

Every screenshot must come from the running team system. Use this caption format in the report:

`Full Student Name - API call title - what it does`

Keep the required endpoint path unchanged and put the responsible student's full name in the route documentation, Postman description, and report section.

