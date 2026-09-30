PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 10000;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS user_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    route_code TEXT NOT NULL,
    display_name TEXT NOT NULL,
    outbound_tag TEXT NOT NULL,
    uuid TEXT NOT NULL UNIQUE,
    xray_email TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    traffic_used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (traffic_used_bytes >= 0),
    last_uplink_bytes INTEGER NOT NULL DEFAULT 0 CHECK (last_uplink_bytes >= 0),
    last_downlink_bytes INTEGER NOT NULL DEFAULT 0 CHECK (last_downlink_bytes >= 0),
    last_counter_epoch INTEGER NOT NULL DEFAULT 0 CHECK (last_counter_epoch >= 0),
    assigned_at TEXT NOT NULL,
    unassigned_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_routes_active_user_route
    ON user_routes(user_id, route_code) WHERE active = 1;
CREATE INDEX IF NOT EXISTS idx_user_routes_user_active
    ON user_routes(user_id, active);
CREATE INDEX IF NOT EXISTS idx_user_routes_outbound_active
    ON user_routes(outbound_tag, active);

INSERT OR IGNORE INTO schema_migrations(version, description, applied_at)
VALUES ('002_ix_routes', 'IX shared route credentials and per-user V2Ray traffic counters', datetime('now'));

INSERT INTO system_settings(setting_key, setting_value, updated_at)
VALUES ('ix_route_management_stage', 'ixr_unified_v2', datetime('now'))
ON CONFLICT(setting_key) DO UPDATE SET
    setting_value = excluded.setting_value,
    updated_at = excluded.updated_at;

PRAGMA user_version = 2;

COMMIT;
