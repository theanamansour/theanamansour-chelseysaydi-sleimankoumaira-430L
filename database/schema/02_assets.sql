-- Service 2: Asset Management Service (Sleiman Koumaira)

CREATE TABLE IF NOT EXISTS assets (
    asset_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name       TEXT NOT NULL,
    asset_type       TEXT NOT NULL CHECK(asset_type IN (
                         'Server', 'Workstation', 'Database', 'Application',
                         'Network Device', 'Cloud Resource'
                     )),
    ip_address       TEXT NOT NULL,
    operating_system TEXT,
    owner_id         INTEGER NOT NULL,
    department       TEXT NOT NULL,
    location         TEXT,
    criticality      TEXT NOT NULL
                     CHECK(criticality IN ('Low', 'Medium', 'High', 'Critical')),
    status           TEXT NOT NULL DEFAULT 'Active'
                     CHECK(status IN ('Active', 'Inactive', 'Under Maintenance')),
    FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS assets_owner ON assets(owner_id);
