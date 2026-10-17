-- Service 9: Security Playbook and Response Automation Service (Chelsea Saydi)

CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_name    TEXT NOT NULL UNIQUE
                     CHECK(length(trim(playbook_name)) BETWEEN 1 AND 150),
    description      TEXT NOT NULL CHECK(length(trim(description)) BETWEEN 1 AND 2000),
    incident_category TEXT NOT NULL
                     CHECK(length(trim(incident_category)) BETWEEN 1 AND 100),
    severity         TEXT NOT NULL
                     CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    created_by       INTEGER NOT NULL,
    created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id        INTEGER NOT NULL,
    action_description TEXT NOT NULL
                       CHECK(length(trim(action_description)) BETWEEN 1 AND 1000),
    step_number        INTEGER NOT NULL CHECK(step_number > 0),
    status             TEXT NOT NULL DEFAULT 'Pending'
                       CHECK(status IN ('Pending', 'In Progress', 'Completed')),
    assigned_user_id   INTEGER,
    completion_date    TEXT,
    FOREIGN KEY(playbook_id) REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
    FOREIGN KEY(assigned_user_id) REFERENCES users(id),
    UNIQUE(playbook_id, step_number)
);

CREATE INDEX IF NOT EXISTS response_actions_playbook
    ON response_actions(playbook_id);
CREATE INDEX IF NOT EXISTS response_actions_assigned_user
    ON response_actions(assigned_user_id);

CREATE TABLE IF NOT EXISTS response_action_history (
    history_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id        INTEGER NOT NULL,
    previous_status  TEXT,
    new_status       TEXT NOT NULL
                     CHECK(new_status IN ('Pending', 'In Progress', 'Completed')),
    changed_by       INTEGER NOT NULL,
    assigned_user_id INTEGER,
    changed_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(action_id) REFERENCES response_actions(action_id) ON DELETE CASCADE,
    FOREIGN KEY(changed_by) REFERENCES users(id),
    FOREIGN KEY(assigned_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS response_action_history_action
    ON response_action_history(action_id);
