-- Service 1: Users and Identity Management Service (Theana Mansour)

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name      TEXT NOT NULL CHECK(length(trim(full_name)) BETWEEN 1 AND 150),
    username       TEXT NOT NULL COLLATE NOCASE
                   CHECK(length(trim(username)) BETWEEN 3 AND 50),
    email          TEXT NOT NULL COLLATE NOCASE
                   CHECK(length(trim(email)) BETWEEN 3 AND 254),
    password_hash  TEXT NOT NULL,
    department     TEXT NOT NULL CHECK(length(trim(department)) BETWEEN 1 AND 100),
    role           TEXT NOT NULL DEFAULT 'Regular Employee'
                   CHECK(role IN (
                       'Security Administrator', 'Security Analyst',
                       'Regular Employee', 'Auditor'
                   )),
    account_status TEXT NOT NULL DEFAULT 'Active'
                   CHECK(account_status IN ('Active', 'Inactive', 'Suspended')),
    created_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at  TEXT,
    UNIQUE(username),
    UNIQUE(email)
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase
    ON users(username COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_nocase
    ON users(email COLLATE NOCASE);
