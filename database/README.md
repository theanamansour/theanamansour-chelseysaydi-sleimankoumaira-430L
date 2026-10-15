# Shared Database

All services use one local SQLite database at `database/data/security_system.db`.
The generated `.db` file stays outside Git. The committed SQL files are the source
of truth for the database structure.

Initialize the database from the repository root:

```powershell
python -m database.init_db
```

Override the local path when needed:

```powershell
$env:SYSTEM_DATABASE_PATH = "C:\path\to\security_system.db"
python -m database.init_db
```

Every service must enable `PRAGMA foreign_keys = ON` for each SQLite connection.
Every service must also use the same `SYSTEM_DATABASE_PATH`. Automatic audit
requests must use the same `INTERNAL_SERVICE_KEY` as Service 5; `.env.example`
lists the shared configuration names without containing real secrets.

To copy existing Service 1 users from the old ignored `services/users/users.db`
without deleting either database:

```powershell
python -m database.migrate_legacy_users
```
