"""
DEVELOPMENT ONLY - prints test tokens for the four roles.

Service 1 (login) is built by a teammate. Until POST /users/login exists, run
    python -m shared.dev_tokens
and paste the tokens into Postman. Once Service 1 works, delete this file and
get tokens by logging in instead.
"""
from shared.auth import ADMIN, ANALYST, AUDITOR, REGULAR_USER, create_access_token

DEV_USERS = [
    (1, "dev_admin", ADMIN),
    (2, "dev_analyst", ANALYST),
    (3, "dev_employee", REGULAR_USER),
    (4, "dev_auditor", AUDITOR),
]

if __name__ == "__main__":
    print("DEVELOPMENT TOKENS (valid for 8 hours) - not real logins\n")
    for user_id, username, role in DEV_USERS:
        token = create_access_token(user_id, username, role, expires_in_minutes=8 * 60)
        print(f"{role} (user_id={user_id}):\n{token}\n")
