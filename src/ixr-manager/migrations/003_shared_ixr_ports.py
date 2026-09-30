#!/usr/bin/env python3
import json
import os
import shutil
import sqlite3
import sys
import uuid
from pathlib import Path

BASE = Path(os.environ.get('IXR_BASE', '/opt/ixr-manager'))
DATA = BASE / 'data'
USERS_DB = Path(os.environ.get('IXR_USERS_DB', str(DATA / 'users.db')))
STATE = Path(os.environ.get('IXR_STATE_FILE', str(DATA / 'state.json')))
USAGE = Path(os.environ.get('IXR_USAGE_FILE', str(DATA / 'usage.json')))
MIGRATION_VERSION = '003_shared_ixr_ports'
MANAGED_EMAIL_SUFFIX = '@ixr.local'


def read_json(path, default):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
        return value if value is not None else default
    except Exception:
        return default


def valid_uuid(value):
    try:
        return str(uuid.UUID(str(value or '').strip()))
    except (ValueError, AttributeError, TypeError):
        return ''


def managed_email(value):
    email = str(value or '').strip()
    return email if email.lower().endswith(MANAGED_EMAIL_SUFFIX) else ''


def new_email(user_id, port, used_emails):
    while True:
        email = f'u{int(user_id):06d}.p{int(port)}.{uuid.uuid4().hex[:8]}{MANAGED_EMAIL_SUFFIX}'
        if email.lower() not in used_emails:
            return email


def state_catalog():
    state = read_json(STATE, {})
    catalog = {}
    for item in state.get('ports') or []:
        if not isinstance(item, dict):
            continue
        port = int(item.get('port') or 0)
        if port <= 0:
            continue
        catalog[port] = {
            'uuid': valid_uuid(item.get('uuid')),
            'email': managed_email(item.get('email')),
        }
    return catalog


def usage_snapshot():
    usage = read_json(USAGE, {})
    rows = usage.get('managed_users')
    if not isinstance(rows, list):
        rows = usage.get('ix_users') if isinstance(usage.get('ix_users'), list) else []
    totals = {}
    for item in rows:
        if not isinstance(item, dict):
            continue
        email = str(item.get('email') or '').strip()
        if not email:
            continue
        totals[email] = {
            'uplink': max(0, int(item.get('uplink') or 0)),
            'downlink': max(0, int(item.get('downlink') or 0)),
        }
    epoch = max(0, int(usage.get('managed_user_started_at') or usage.get('ix_user_started_at') or usage.get('xray_started_at') or 0))
    return totals, epoch


def table_columns(database, table):
    return {str(row[1]) for row in database.execute(f'PRAGMA table_info({table})')}


def migration_applied(database):
    row = database.execute('SELECT 1 FROM schema_migrations WHERE version = ?', (MIGRATION_VERSION,)).fetchone()
    return row is not None


def ensure_schema(database):
    columns = table_columns(database, 'user_ports')
    additions = {
        'uuid': 'TEXT',
        'xray_email': 'TEXT',
        'last_uplink_bytes': 'INTEGER NOT NULL DEFAULT 0',
        'last_downlink_bytes': 'INTEGER NOT NULL DEFAULT 0',
    }
    for name, definition in additions.items():
        if name not in columns:
            database.execute(f'ALTER TABLE user_ports ADD COLUMN {name} {definition}')
    database.execute('DROP INDEX IF EXISTS idx_user_ports_active_port')


def backfill_credentials(database):
    catalog = state_catalog()
    totals, epoch = usage_snapshot()
    rows = database.execute(
        '''
        SELECT id, user_id, port, active, uuid, xray_email,
               last_uplink_bytes, last_downlink_bytes
        FROM user_ports
        ORDER BY active DESC, id
        '''
    ).fetchall()
    used_uuids = set()
    used_emails = set()
    for row in rows:
        current_uuid = valid_uuid(row['uuid'])
        current_email = managed_email(row['xray_email'])
        if current_uuid:
            if current_uuid in used_uuids:
                current_uuid = ''
            else:
                used_uuids.add(current_uuid)
        if current_email:
            lowered = current_email.lower()
            if lowered in used_emails:
                current_email = ''
            else:
                used_emails.add(lowered)

    updated = 0
    used_uuids.clear()
    used_emails.clear()
    for row in rows:
        assignment_id = int(row['id'])
        user_id = int(row['user_id'])
        port = int(row['port'])
        active = int(row['active'] or 0) == 1
        port_state = catalog.get(port, {})
        credential_uuid = valid_uuid(row['uuid'])
        if not credential_uuid or credential_uuid in used_uuids:
            candidate = port_state.get('uuid', '') if active else ''
            if candidate and candidate not in used_uuids:
                credential_uuid = candidate
            else:
                credential_uuid = str(uuid.uuid4())
        used_uuids.add(credential_uuid)

        email = managed_email(row['xray_email'])
        if not email or email.lower() in used_emails:
            candidate = port_state.get('email', '') if active else ''
            if candidate and candidate.lower() not in used_emails:
                email = candidate
            else:
                email = new_email(user_id, port, used_emails)
        used_emails.add(email.lower())

        counter = totals.get(email, {}) if active else {}
        uplink = max(0, int(counter.get('uplink') or 0))
        downlink = max(0, int(counter.get('downlink') or 0))
        counter_epoch = epoch if active else 0
        database.execute(
            '''
            UPDATE user_ports
            SET uuid = ?, xray_email = ?, last_uplink_bytes = ?,
                last_downlink_bytes = ?, last_counter_bytes = ?,
                last_counter_epoch = ?
            WHERE id = ?
            ''',
            (credential_uuid, email, uplink, downlink, uplink + downlink, counter_epoch, assignment_id),
        )
        updated += 1
    return updated


def create_indexes(database):
    database.execute(
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_user_ports_active_user_port ON user_ports(user_id, port) WHERE active = 1'
    )
    database.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_user_ports_uuid ON user_ports(uuid)')
    database.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_user_ports_xray_email ON user_ports(xray_email)')
    database.execute('CREATE INDEX IF NOT EXISTS idx_user_ports_port_active ON user_ports(port, active)')


def ensure_permissions():
    for path in (USERS_DB, Path(str(USERS_DB) + '-wal'), Path(str(USERS_DB) + '-shm')):
        if not path.exists():
            continue
        try:
            os.chmod(path, 0o660)
            shutil.chown(path, 'www-data', 'www-data')
        except Exception:
            pass


def main():
    if not USERS_DB.is_file():
        print('ERROR: IXR 用户数据库不存在', file=sys.stderr)
        return 2
    database = sqlite3.connect(USERS_DB, timeout=30)
    database.row_factory = sqlite3.Row
    database.execute('PRAGMA foreign_keys = ON')
    database.execute('PRAGMA busy_timeout = 30000')
    try:
        database.execute('BEGIN IMMEDIATE')
        ensure_schema(database)
        already_applied = migration_applied(database)
        missing_before = int(database.execute(
            "SELECT COUNT(*) FROM user_ports WHERE uuid IS NULL OR uuid = '' OR xray_email IS NULL OR xray_email = ''"
        ).fetchone()[0] or 0)
        updated = 0 if already_applied and missing_before == 0 else backfill_credentials(database)
        create_indexes(database)
        missing = database.execute(
            "SELECT COUNT(*) FROM user_ports WHERE uuid IS NULL OR uuid = '' OR xray_email IS NULL OR xray_email = ''"
        ).fetchone()[0]
        if int(missing or 0) != 0:
            raise RuntimeError('IXR 端口凭证回填不完整')
        database.execute(
            '''
            INSERT OR IGNORE INTO schema_migrations(version, description, applied_at)
            VALUES (?, 'IXR shared-port per-user Xray credentials and counters', datetime('now'))
            ''',
            (MIGRATION_VERSION,),
        )
        database.execute('PRAGMA user_version = 3')
        database.commit()
    except Exception:
        database.rollback()
        raise
    finally:
        database.close()
        ensure_permissions()
    print(f'OK: shared IXR port migration applied; assignments={updated}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
