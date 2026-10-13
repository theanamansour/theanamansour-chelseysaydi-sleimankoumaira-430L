-- Service 2: Asset Management Service (Sleiman Koumaira)
-- Stores organizational assets that may be affected by security incidents.

CREATE TABLE IF NOT EXISTS assets (
    asset_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name       TEXT    NOT NULL,
    asset_type       TEXT    NOT NULL
                     CHECK (asset_type IN ('Server', 'Workstation', 'Database', 'Application',
                                           'Network Device', 'Cloud Resource')),
    ip_address       TEXT    NOT NULL,
    operating_system TEXT,                -- optional: not every asset has an operating system
    -- The user who owns the asset: a users.id from Service 1 (Users and Identity).
    -- Service 1 keeps its own database, so this cannot be a SQLite FOREIGN KEY; instead the
    -- API checks with Service 1 that the user exists before saving (a logical foreign key).
    owner_id         INTEGER NOT NULL,
    department       TEXT    NOT NULL,
    location         TEXT,                -- optional
    criticality      TEXT    NOT NULL
                     CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical')),
    status           TEXT    NOT NULL DEFAULT 'Active'
                     CHECK (status IN ('Active', 'Inactive', 'Under Maintenance'))
);
