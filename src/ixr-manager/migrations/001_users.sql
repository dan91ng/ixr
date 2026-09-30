PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 10000;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    subscription_token TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'quota_exhausted', 'expired')),
    traffic_limit_bytes INTEGER CHECK (traffic_limit_bytes IS NULL OR traffic_limit_bytes > 0),
    expires_at TEXT,
    last_login_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    label TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    traffic_used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (traffic_used_bytes >= 0),
    last_counter_bytes INTEGER NOT NULL DEFAULT 0 CHECK (last_counter_bytes >= 0),
    last_counter_epoch INTEGER NOT NULL DEFAULT 0 CHECK (last_counter_epoch >= 0),
    assigned_at TEXT NOT NULL,
    unassigned_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_ports_active_port
    ON user_ports(port) WHERE active = 1;
CREATE INDEX IF NOT EXISTS idx_user_ports_user_active
    ON user_ports(user_id, active);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER,
    details_json TEXT,
    success INTEGER NOT NULL DEFAULT 1 CHECK (success IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
    ON audit_logs(created_at);

CREATE TABLE IF NOT EXISTS system_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migrations(version, description, applied_at)
VALUES ('001_users', 'IXR users, active port assignments, quota counters and audit log', datetime('now'));

INSERT INTO system_settings(setting_key, setting_value, updated_at)
VALUES ('user_management_stage', 'ixr_native_v1', datetime('now'))
ON CONFLICT(setting_key) DO UPDATE SET
    setting_value = excluded.setting_value,
    updated_at = excluded.updated_at;

PRAGMA user_version = 1;

COMMIT;
