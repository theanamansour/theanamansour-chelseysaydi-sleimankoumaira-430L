from services.playbooks.database import get_db

MAX_SQLITE_ID = 2**63 - 1


def playbook_to_dict(row):
    return {
        "playbook_id": row["playbook_id"],
        "playbook_name": row["playbook_name"],
        "description": row["description"],
        "incident_category": row["incident_category"],
        "severity": row["severity"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }


def history_to_dict(row):
    return {
        "history_id": row["history_id"],
        "action_id": row["action_id"],
        "previous_status": row["previous_status"],
        "new_status": row["new_status"],
        "changed_by": row["changed_by"],
        "assigned_user_id": row["assigned_user_id"],
        "changed_at": row["changed_at"],
    }


def action_to_dict(row, history=None):
    action = {
        "action_id": row["action_id"],
        "playbook_id": row["playbook_id"],
        "action_description": row["action_description"],
        "step_number": row["step_number"],
        "status": row["status"],
        "assigned_user_id": row["assigned_user_id"],
        "completion_date": row["completion_date"],
    }
    if history is not None:
        action["history"] = [history_to_dict(item) for item in history]
    return action


class PlaybookRepository:
    def __init__(self, database_path):
        self.database_path = database_path

    def create(self, data, created_by):
        with get_db(self.database_path) as db:
            cursor = db.execute(
                """
                INSERT INTO playbooks
                    (playbook_name, description, incident_category,
                     severity, created_by)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    data["playbook_name"],
                    data["description"],
                    data["incident_category"],
                    data["severity"],
                    created_by,
                ),
            )
            playbook_id = cursor.lastrowid
        return self.get(playbook_id)

    def all(self):
        with get_db(self.database_path) as db:
            rows = db.execute(
                "SELECT * FROM playbooks ORDER BY playbook_id"
            ).fetchall()
        return [playbook_to_dict(row) for row in rows]

    def get(self, playbook_id):
        if playbook_id > MAX_SQLITE_ID:
            return None
        with get_db(self.database_path) as db:
            row = db.execute(
                "SELECT * FROM playbooks WHERE playbook_id = ?",
                (playbook_id,),
            ).fetchone()
            if row is None:
                return None
            action_rows = db.execute(
                """
                SELECT * FROM response_actions
                WHERE playbook_id = ? ORDER BY step_number
                """,
                (playbook_id,),
            ).fetchall()
            actions = []
            for action_row in action_rows:
                history = db.execute(
                    """
                    SELECT * FROM response_action_history
                    WHERE action_id = ? ORDER BY history_id
                    """,
                    (action_row["action_id"],),
                ).fetchall()
                actions.append(action_to_dict(action_row, history))

        playbook = playbook_to_dict(row)
        playbook["actions"] = actions
        return playbook

    def add_action(self, playbook_id, data, created_by):
        if playbook_id > MAX_SQLITE_ID:
            return None
        with get_db(self.database_path) as db:
            exists = db.execute(
                "SELECT 1 FROM playbooks WHERE playbook_id = ?",
                (playbook_id,),
            ).fetchone()
            if exists is None:
                return None
            cursor = db.execute(
                """
                INSERT INTO response_actions
                    (playbook_id, action_description, step_number)
                VALUES (?, ?, ?)
                """,
                (
                    playbook_id,
                    data["action_description"],
                    data["step_number"],
                ),
            )
            action_id = cursor.lastrowid
            db.execute(
                """
                INSERT INTO response_action_history
                    (action_id, previous_status, new_status, changed_by)
                VALUES (?, NULL, 'Pending', ?)
                """,
                (action_id, created_by),
            )
        return self.get_action(action_id)

    def get_action(self, action_id):
        if action_id > MAX_SQLITE_ID:
            return None
        with get_db(self.database_path) as db:
            row = db.execute(
                "SELECT * FROM response_actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
            if row is None:
                return None
            history = db.execute(
                """
                SELECT * FROM response_action_history
                WHERE action_id = ? ORDER BY history_id
                """,
                (action_id,),
            ).fetchall()
        return action_to_dict(row, history)

    def earlier_actions_complete(self, action):
        with get_db(self.database_path) as db:
            unfinished = db.execute(
                """
                SELECT 1 FROM response_actions
                WHERE playbook_id = ?
                  AND step_number < ?
                  AND status != 'Completed'
                LIMIT 1
                """,
                (action["playbook_id"], action["step_number"]),
            ).fetchone()
        return unfinished is None

    def update_action(self, action_id, status, assigned_user_id, changed_by):
        current = self.get_action(action_id)
        if current is None:
            return None

        assignment = (
            assigned_user_id
            if assigned_user_id is not None
            else current["assigned_user_id"]
        )
        completion_sql = (
            "CURRENT_TIMESTAMP" if status == "Completed" else "NULL"
        )
        with get_db(self.database_path) as db:
            db.execute(
                f"""
                UPDATE response_actions
                SET status = ?, assigned_user_id = ?,
                    completion_date = {completion_sql}
                WHERE action_id = ?
                """,
                (status, assignment, action_id),
            )
            db.execute(
                """
                INSERT INTO response_action_history
                    (action_id, previous_status, new_status,
                     changed_by, assigned_user_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    action_id,
                    current["status"],
                    status,
                    changed_by,
                    assignment,
                ),
            )
        return self.get_action(action_id)

    def delete(self, playbook_id):
        if playbook_id > MAX_SQLITE_ID:
            return False
        with get_db(self.database_path) as db:
            cursor = db.execute(
                "DELETE FROM playbooks WHERE playbook_id = ?",
                (playbook_id,),
            )
            return cursor.rowcount > 0
