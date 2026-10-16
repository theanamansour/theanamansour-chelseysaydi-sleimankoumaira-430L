# Service 1 API Documentation — Theana Mansour

Base URL: `http://127.0.0.1:5001/theana-mansour`

Service 1 manages user accounts, password authentication, roles and account status.
It also issues the tokens that every other service checks through
`POST /auth/verify`.

- Users are stored in the shared SQLite database (`users` table,
  `database/schema/01_users.sql`).
- Passwords are stored only as Werkzeug hashes and are never returned.
- Tokens are JWTs signed with HS256. They expire after one hour.
- Protected requests need `Authorization: Bearer <token>`.
- Every query uses bound parameters, so text such as `' OR '1'='1` is stored and
  compared as plain data.
- Security events are sent to Service 5 on a best-effort basis. If Service 5 is down,
  the user operation still succeeds.

Run from the repository root:

```powershell
$env:INTERNAL_SERVICE_KEY = "same-value-as-service-5"
python -m database.init_db
python -m services.users.create_admin
python -m services.users.app
```

## Roles

| Endpoint | Security Administrator | Regular Employee | Auditor | Security Analyst |
|---|---|---|---|---|
| `POST /users/register` | any role | Regular Employee only | Regular Employee only | Regular Employee only |
| `POST /users/login` | yes | yes | yes | yes |
| `PUT /users/{id}` | any user | own account only | no | no |
| `DELETE /users/{id}` | any user except self | no | no | no |
| `GET /users` | yes | no | yes | no |
| `GET /users/{username}` | any user | own account only | any user | no |
| `PUT /users/{id}/role` | any user except self | no | no | no |
| `PUT /users/{id}/status` | any user except self | no | no | no |
| `POST /auth/verify` | used by other services with the caller's token | | | |

`Regular User` is accepted as another name for `Regular Employee` and is saved as
`Regular Employee`.

## Error Format

Every error uses the same body:

```json
{ "status": "error", "message": "Permission denied" }
```

## 1. User Registration

- Method/route: `POST /users/register`
- Purpose: create an account. Anyone may create a `Regular Employee`. Only a Security
  Administrator (bearer token) may create any other role.
- Body (all required):

```json
{
  "full_name": "Theana Mansour",
  "username": "theana",
  "email": "theana@example.com",
  "password": "Passw0rd1",
  "department": "IT",
  "role": "Regular Employee"
}
```

- Validation:
  - every field is required and must be text
  - the email must have a valid format
  - the username must be 3–50 characters and unique, ignoring capital letters
  - the email must be unique
  - the password needs at least 8 characters, with at least one letter and one number
  - the full name can be up to 150 characters and the department up to 100
  - the role must be one of the four roles
- `201`:

```json
{ "message": "User registered successfully", "user_id": 5, "role": "Regular Employee" }
```

- Errors:
  - `400`: missing or invalid field
  - `401`: privileged role without a token
  - `403`: privileged role requested by someone who isn't an administrator
  - `409`: `Username already exists` or `Email already exists`

## 2. User Login

- Method/route: `POST /users/login`
- Body: `{ "login": "theana", "password": "Passw0rd1" }`. The `login` field accepts a
  username or an email.
- `200`:

```json
{ "message": "Login successful", "token": "<JWT>", "role": "Regular Employee", "user_id": 5 }
```

- The token contains `sub`, `user_id`, `username`, `role`, `iat` and `exp` (one hour).
  `last_login_at` is updated.
- Errors:
  - `400`: login or password missing
  - `401`: `Invalid credentials`
  - `403`: `Account is not active` (Inactive or Suspended)

## 3. Update User Information

- Method/route: `PUT /users/{id}`
- Roles: Security Administrator (any user); Regular Employee (own account only)
- Body: any of `full_name`, `email`, `department`. Example:

```json
{ "department": "Finance" }
```

- `200`:

```json
{ "message": "User updated successfully", "user": { "id": 5, "full_name": "...", "username": "...", "email": "...", "department": "Finance", "role": "...", "account_status": "Active", "created_at": "...", "last_login_at": "..." } }
```

- Errors:
  - `400`: unknown field (for example `role`), empty value, bad email or too long
  - `401`: no token or invalid token
  - `403`: not allowed
  - `404`: user not found
  - `409`: email already used

## 4. Delete User

- Method/route: `DELETE /users/{id}`
- Role: Security Administrator. Administrators can't delete their own account.
- `200`: `{ "message": "User deleted successfully" }`
- Errors:
  - `401`: no token or invalid token
  - `403`: other roles, or deleting yourself
  - `404`: user not found
  - `409`: other records still point to this user (for example assets or incidents)

## 5. Retrieve All Users

- Method/route: `GET /users`
- Roles: Security Administrator, Auditor
- `200`: a JSON array of users. Each user has `id`, `full_name`, `username`, `email`,
  `department`, `role`, `account_status`, `created_at` and `last_login_at`. The
  password hash is never included.
- Errors: `401`, `403`

## 6. Retrieve User By Username

- Method/route: `GET /users/{username}`
- Roles: Security Administrator, Auditor (any user); Regular Employee (own account)
- `200`: one user object (same fields as above)
- Errors:
  - `401`: no token or invalid token
  - `403`: an employee asking for someone else
  - `404`: `User not found`

## 7. Change User Role (administrator)

- Method/route: `PUT /users/{id}/role`
- Body: `{ "role": "Security Analyst" }`
- `200`: `{ "message": "User role updated successfully" }`
- Errors:
  - `400`: invalid role or extra fields
  - `403`: not an administrator, or changing your own role
  - `404`: user not found

## 8. Change Account Status (administrator)

- Method/route: `PUT /users/{id}/status`
- Body: `{ "status": "Suspended" }`. Allowed values: `Active`, `Inactive`, `Suspended`.
- A Suspended or Inactive user can't log in, and their existing tokens stop working
  straight away.
- `200`: `{ "message": "Account status updated successfully" }`
- Errors:
  - `400`: invalid status
  - `403`: not an administrator, or changing your own status
  - `404`: user not found

## 9. Verify Token (used by other services)

- Method/route: `POST /auth/verify`
- Header: `Authorization: Bearer <token>`
- `200`:

```json
{ "valid": true, "user_id": 5, "username": "theana", "role": "Regular Employee" }
```

- `401` returns `{ "status": "error", "message": "...", "valid": false }`. This happens
  when the token is missing, malformed, expired or signed with another key, or when the
  user was deleted, suspended or made inactive. Every call reads the user's current
  record from the database.

## Audit Events Sent to Service 5

`REGISTER_USER`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_BLOCKED`, `UPDATE_USER`,
`DELETE_USER`, `UPDATE_USER_ROLE`, `UPDATE_ACCOUNT_STATUS`, `PERMISSION_DENIED`,
`UNAUTHENTICATED_ACCESS`.

Each event is sent to `AUDIT_LOG_URL` with the `X-Service-Key: <INTERNAL_SERVICE_KEY>`
header. Service 1 and Service 5 must be started with the same `INTERNAL_SERVICE_KEY`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SYSTEM_DATABASE_PATH` | `database/data/security_system.db` | Shared database file |
| `JWT_SECRET_KEY` | random key saved in the ignored `services/users/.secret_key` | Token signing key |
| `INTERNAL_SERVICE_KEY` | random key saved in the ignored `.internal_service_key` | Key for calls between services |
| `USER_SERVICE_PORT` | `5001` | Port |
| `AUDIT_LOG_URL` | `http://127.0.0.1:5005/chelsea-saydi/logs` | Service 5 address |
| `SERVICE_REQUEST_TIMEOUT` | `1` | Seconds to wait for Service 5 |
