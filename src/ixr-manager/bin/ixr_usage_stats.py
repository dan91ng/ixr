#!/usr/bin/env python3
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA = Path('/opt/ixr-manager/data')
OUTS = DATA / 'outbounds.json'
STATE = DATA / 'state.json'
USAGE = DATA / 'usage.json'
BASELINE = DATA / 'usage_baseline.json'
USERS_DB = DATA / 'users.db'
IX_LEGACY = DATA / 'ix_legacy.json'
XRAY = '/usr/local/bin/xray'
SERVER = '127.0.0.1:10085'
RUNTIME_SYNC = '/usr/local/bin/ixr-runtime-sync'
MANAGED_EMAIL_SUFFIX = '@ixr.local'


def read_json(path, default):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        return data if data is not None else default
    except Exception:
        return default


def write_json(path, data):
    tmp = Path(str(path) + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(tmp, path)


def ensure_user_database_permissions():
    for path in (USERS_DB, Path(str(USERS_DB) + '-wal'), Path(str(USERS_DB) + '-shm')):
        if not path.exists():
            continue
        try:
            os.chmod(path, 0o660)
            shutil.chown(path, 'www-data', 'www-data')
        except Exception:
            pass


def synchronize_runtime(reason):
    try:
        result = subprocess.run(
            [RUNTIME_SYNC, str(reason)[:200]],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
        )
        if result.returncode != 0:
            output = (result.stdout or '').replace('\n', ' | ')[-1200:]
            print(f'WARNING: Xray 用户动态收敛失败（退出码 {result.returncode}）：{output}')
            return False
        print('OK: Xray 用户动态收敛已执行，无需重启服务')
        return True
    except subprocess.TimeoutExpired:
        print('WARNING: Xray 用户动态收敛超时（90 秒）')
        return False
    except Exception as exc:
        print(f'WARNING: 无法执行 Xray 用户动态收敛：{exc}')
        return False


def effective_user_status(row, used_bytes, now_text):
    if int(row['enabled'] or 0) != 1:
        return 'disabled'
    expires_at = str(row['expires_at'] or '').strip()
    if expires_at and expires_at <= now_text:
        return 'expired'
    limit = row['traffic_limit_bytes']
    if limit is not None and int(used_bytes) >= int(limit):
        return 'quota_exhausted'
    return 'active'

def sync_user_accounting(
    user_totals=None,
    user_counter_epoch=0,
    update_port_counters=True,
    update_route_counters=True,
):
    if not USERS_DB.is_file():
        return []
    user_totals = user_totals if isinstance(user_totals, dict) else {}
    now_text = datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
    database = None
    changes = []
    try:
        database = sqlite3.connect(USERS_DB, timeout=10)
        database.row_factory = sqlite3.Row
        database.execute('PRAGMA foreign_keys = ON')
        database.execute('PRAGMA busy_timeout = 10000')
        database.execute('BEGIN IMMEDIATE')
        has_routes = bool(database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_routes'").fetchone())

        if update_port_counters:
            assignments = database.execute(
                '''
                SELECT id, xray_email, traffic_used_bytes, last_uplink_bytes,
                       last_downlink_bytes, last_counter_epoch
                FROM user_ports
                WHERE active = 1
                '''
            ).fetchall()
            for assignment in assignments:
                email = str(assignment['xray_email'] or '')
                values = user_totals.get(email, {}) if isinstance(user_totals.get(email, {}), dict) else {}
                current_uplink = max(0, int(values.get('uplink', 0)))
                current_downlink = max(0, int(values.get('downlink', 0)))
                previous_uplink = max(0, int(assignment['last_uplink_bytes'] or 0))
                previous_downlink = max(0, int(assignment['last_downlink_bytes'] or 0))
                previous_epoch = max(0, int(assignment['last_counter_epoch'] or 0))
                if previous_epoch != int(user_counter_epoch) or current_uplink < previous_uplink:
                    uplink_delta = current_uplink
                else:
                    uplink_delta = current_uplink - previous_uplink
                if previous_epoch != int(user_counter_epoch) or current_downlink < previous_downlink:
                    downlink_delta = current_downlink
                else:
                    downlink_delta = current_downlink - previous_downlink
                database.execute(
                    '''
                    UPDATE user_ports
                    SET traffic_used_bytes = traffic_used_bytes + ?,
                        last_counter_bytes = ?,
                        last_uplink_bytes = ?,
                        last_downlink_bytes = ?,
                        last_counter_epoch = ?,
                        updated_at = ?
                    WHERE id = ?
                    ''',
                    (
                        max(0, uplink_delta) + max(0, downlink_delta),
                        current_uplink + current_downlink,
                        current_uplink,
                        current_downlink,
                        max(0, int(user_counter_epoch)),
                        now_text,
                        int(assignment['id']),
                    ),
                )

        if update_route_counters and has_routes:
            assignments = database.execute(
                '''
                SELECT id, xray_email, traffic_used_bytes, last_uplink_bytes,
                       last_downlink_bytes, last_counter_epoch
                FROM user_routes
                WHERE active = 1
                '''
            ).fetchall()
            for assignment in assignments:
                email = str(assignment['xray_email'] or '')
                values = user_totals.get(email, {}) if isinstance(user_totals.get(email, {}), dict) else {}
                current_uplink = max(0, int(values.get('uplink', 0)))
                current_downlink = max(0, int(values.get('downlink', 0)))
                previous_uplink = max(0, int(assignment['last_uplink_bytes'] or 0))
                previous_downlink = max(0, int(assignment['last_downlink_bytes'] or 0))
                previous_epoch = max(0, int(assignment['last_counter_epoch'] or 0))
                if previous_epoch != int(user_counter_epoch) or current_uplink < previous_uplink:
                    uplink_delta = current_uplink
                else:
                    uplink_delta = current_uplink - previous_uplink
                if previous_epoch != int(user_counter_epoch) or current_downlink < previous_downlink:
                    downlink_delta = current_downlink
                else:
                    downlink_delta = current_downlink - previous_downlink
                database.execute(
                    '''
                    UPDATE user_routes
                    SET traffic_used_bytes = traffic_used_bytes + ?,
                        last_uplink_bytes = ?,
                        last_downlink_bytes = ?,
                        last_counter_epoch = ?,
                        updated_at = ?
                    WHERE id = ?
                    ''',
                    (
                        max(0, uplink_delta) + max(0, downlink_delta),
                        current_uplink,
                        current_downlink,
                        max(0, int(user_counter_epoch)),
                        now_text,
                        int(assignment['id']),
                    ),
                )

        route_total_sql = "COALESCE((SELECT SUM(ur.traffic_used_bytes) FROM user_routes ur WHERE ur.user_id = u.id), 0)" if has_routes else '0'
        users = database.execute(
            f'''
            SELECT u.*,
                   COALESCE((SELECT SUM(up.traffic_used_bytes) FROM user_ports up WHERE up.user_id = u.id), 0)
                   + {route_total_sql} AS traffic_used_bytes
            FROM users u
            '''
        ).fetchall()
        for user in users:
            status = effective_user_status(user, int(user['traffic_used_bytes'] or 0), now_text)
            previous_status = str(user['status'] or '')
            if status == previous_status:
                continue
            database.execute('UPDATE users SET status = ?, updated_at = ? WHERE id = ?', (status, now_text, int(user['id'])))
            database.execute(
                '''
                INSERT INTO audit_logs(actor, action, target_type, target_id, details_json, success, created_at)
                VALUES ('system', 'status_auto_changed', 'user', ?, ?, 1, ?)
                ''',
                (
                    int(user['id']),
                    json.dumps({'from': previous_status, 'to': status}, ensure_ascii=False),
                    now_text,
                ),
            )
            changes.append((str(user['username']), previous_status, status))

        database.commit()
    except Exception as exc:
        if database is not None:
            try:
                database.rollback()
            except Exception:
                pass
        print(f'WARNING: 用户流量结算失败：{exc}')
        changes = []
    finally:
        if database is not None:
            database.close()
        ensure_user_database_permissions()
    return changes


def port_out_tag(port, base_tag):
    return f'p{int(port)}-{base_tag}'


def add_values(left, right):
    left['uplink'] = int(left.get('uplink', 0)) + int(right.get('uplink', 0))
    left['downlink'] = int(left.get('downlink', 0)) + int(right.get('downlink', 0))
    return left


def query_stats(pattern):
    result = subprocess.run(
        [XRAY, 'api', 'statsquery', f'--server={SERVER}', '-pattern', pattern],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or '').strip())
    return json.loads(result.stdout or '{}')


def get_process_started_at(pid):
    try:
        pid = int(pid)
        if pid <= 0:
            return 0
        stat_text = Path(f'/proc/{pid}/stat').read_text(encoding='utf-8', errors='replace')
        tail = stat_text.rsplit(') ', 1)[1].split()
        start_ticks = int(tail[19])
        boot_time = 0
        for line in Path('/proc/stat').read_text(encoding='utf-8', errors='replace').splitlines():
            if line.startswith('btime '):
                boot_time = int(line.split()[1])
                break
        if not boot_time:
            return 0
        return int(boot_time + start_ticks / os.sysconf(os.sysconf_names['SC_CLK_TCK']))
    except Exception:
        return 0


def get_xray_started_at():
    try:
        result = subprocess.run(
            ['systemctl', 'show', 'xray', '--property=MainPID', '--value'],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if result.returncode == 0:
            started_at = get_process_started_at((result.stdout or '').strip())
            if started_at:
                return started_at
    except Exception:
        pass
    try:
        result = subprocess.run(
            ['pgrep', '-o', 'xray'],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if result.returncode == 0:
            return get_process_started_at((result.stdout or '').strip())
    except Exception:
        pass
    return 0


def parse_direction_stats(raw, prefix):
    per_tag = {}
    regex = re.compile(rf'^{re.escape(prefix)}>>>(.+?)>>>traffic>>>(uplink|downlink)$')
    for item in raw.get('stat', []) or []:
        name = item.get('name', '')
        value = int(item.get('value') or 0)
        match = regex.match(name)
        if not match:
            continue
        tag, direction = match.groups()
        per_tag.setdefault(tag, {'uplink': 0, 'downlink': 0})[direction] = value
    return per_tag


def parse_user_stats(raw):
    users = {}
    regex = re.compile(r'^user>>>(.+?)>>>traffic>>>(uplink|downlink)$')
    for item in raw.get('stat', []) or []:
        name = str(item.get('name') or '')
        match = regex.match(name)
        if not match:
            continue
        email, direction = match.groups()
        if not email.lower().endswith(MANAGED_EMAIL_SUFFIX):
            continue
        users.setdefault(email, {'uplink': 0, 'downlink': 0})[direction] = max(0, int(item.get('value') or 0))
    return users


def ix_route_assignment_emails():
    if not USERS_DB.is_file():
        return set()
    database = sqlite3.connect(f'file:{USERS_DB}?mode=ro', uri=True, timeout=10)
    try:
        has_routes = bool(database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_routes'").fetchone())
        if not has_routes:
            return set()
        return {
            str(row[0] or '').strip()
            for row in database.execute('SELECT xray_email FROM user_routes')
            if str(row[0] or '').strip()
        }
    finally:
        database.close()



def subtract_baseline_stats(current, baseline):
    baseline = baseline if isinstance(baseline, dict) else {}
    adjusted = {}
    for tag, values in current.items():
        base = baseline.get(tag, {}) if isinstance(baseline.get(tag, {}), dict) else {}
        adjusted[tag] = {
            'uplink': max(0, int(values.get('uplink', 0)) - int(base.get('uplink', 0) or 0)),
            'downlink': max(0, int(values.get('downlink', 0)) - int(base.get('downlink', 0) or 0)),
        }
    return adjusted


def counters_look_reset(current, baseline):
    if not isinstance(baseline, dict) or not baseline:
        return False
    for tag, base_values in baseline.items():
        if not isinstance(base_values, dict):
            continue
        current_values = current.get(tag)
        if not isinstance(current_values, dict):
            continue
        if int(current_values.get('uplink', 0)) < int(base_values.get('uplink', 0) or 0):
            return True
        if int(current_values.get('downlink', 0)) < int(base_values.get('downlink', 0) or 0):
            return True
    return False

def build_node_rows(outbounds, stats_by_tag, total_tags=None):
    rows = []
    for outbound in outbounds:
        values = {'uplink': 0, 'downlink': 0}
        tags = total_tags(outbound) if total_tags else [outbound.get('tag')]
        for tag in tags:
            add_values(values, stats_by_tag.get(tag, {'uplink': 0, 'downlink': 0}))
        total = int(values.get('uplink', 0)) + int(values.get('downlink', 0))
        rows.append({
            'name': outbound.get('name'),
            'tag': outbound.get('tag'),
            'port': outbound.get('port'),
            'uplink': int(values.get('uplink', 0)),
            'downlink': int(values.get('downlink', 0)),
            'total': total,
        })
    total_bytes = sum(row['total'] for row in rows)
    for row in rows:
        row['percent'] = round(row['total'] * 100 / total_bytes, 2) if total_bytes else 0
    rows.sort(key=lambda row: (-row['total'], str(row.get('name') or '')))
    return rows, total_bytes


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    outbounds = read_json(OUTS, [])
    state = read_json(STATE, {'ports': []})
    port_configs = state.get('ports') if isinstance(state, dict) else []
    if not isinstance(port_configs, list):
        port_configs = []
    previous_payload = read_json(USAGE, {})
    if not isinstance(previous_payload, dict):
        previous_payload = {}
    managed_ports = []
    for port_config in port_configs:
        try:
            managed_ports.append(int(port_config.get('port')))
        except Exception:
            continue

    xray_available = False
    xray_error = ''
    reset_at = max(0, int(previous_payload.get('stats_since_at') or 0))
    xray_started_at = get_xray_started_at()
    baseline_reset_at = 0
    baseline_stale = False
    basis = str(previous_payload.get('basis') or 'xray traffic counters unavailable')
    nodes = previous_payload.get('nodes', []) if isinstance(previous_payload.get('nodes', []), list) else []
    ports = previous_payload.get('ports', []) if isinstance(previous_payload.get('ports', []), list) else []
    outbounds_by_port = previous_payload.get('outbounds_by_port', []) if isinstance(previous_payload.get('outbounds_by_port', []), list) else []
    total_bytes = max(0, int(previous_payload.get('total_bytes') or 0))
    port_total_bytes = max(0, int(previous_payload.get('port_total_bytes') or 0))
    port_totals = {}
    try:
        raw_outbound_stats = parse_direction_stats(query_stats('outbound>>>'), 'outbound')
        raw_inbound_stats = parse_direction_stats(query_stats('inbound>>>'), 'inbound')
        baseline = read_json(BASELINE, {}) or {}
        baseline_reset_at = int(baseline.get('reset_at') or 0) if isinstance(baseline, dict) else 0
        baseline_outbound = baseline.get('outbound', {}) if isinstance(baseline, dict) else {}
        baseline_inbound = baseline.get('inbound', {}) if isinstance(baseline, dict) else {}
        baseline_stale = bool(xray_started_at and baseline_reset_at and xray_started_at > baseline_reset_at + 5)
        if not baseline_stale:
            baseline_stale = counters_look_reset(raw_outbound_stats, baseline_outbound) or counters_look_reset(raw_inbound_stats, baseline_inbound)
        if baseline_stale:
            reset_at = xray_started_at or int(time.time())
            outbound_stats = raw_outbound_stats
            inbound_stats = raw_inbound_stats
            basis = 'xray traffic counters since current xray process start'
        else:
            reset_at = baseline_reset_at or xray_started_at or 0
            outbound_stats = subtract_baseline_stats(raw_outbound_stats, baseline_outbound)
            inbound_stats = subtract_baseline_stats(raw_inbound_stats, baseline_inbound)
            basis = 'xray traffic counters since last manual stats reset' if baseline_reset_at else 'xray traffic counters since current xray process start'

        nodes, total_bytes = build_node_rows(
            outbounds,
            outbound_stats,
            total_tags=lambda outbound: [outbound.get('tag')] + [port_out_tag(port, outbound.get('tag')) for port in managed_ports],
        )
        ports = []
        outbounds_by_port = []
        for port_config in port_configs:
            try:
                port = int(port_config.get('port'))
            except Exception:
                continue
            inbound_tag = f'in-{port}'
            values = inbound_stats.get(inbound_tag, {'uplink': 0, 'downlink': 0})
            inbound_total = int(values.get('uplink', 0)) + int(values.get('downlink', 0))
            rules = port_config.get('rules') if isinstance(port_config.get('rules'), list) else []
            ports.append({
                'port': port,
                'tag': inbound_tag,
                'uplink': int(values.get('uplink', 0)),
                'downlink': int(values.get('downlink', 0)),
                'total': inbound_total,
                'rules': len(rules),
                'default': port_config.get('default') or 'auto-fast',
                'email': port_config.get('email') or '',
            })
            port_nodes, port_out_total = build_node_rows(
                outbounds,
                outbound_stats,
                total_tags=lambda outbound, current_port=port: [port_out_tag(current_port, outbound.get('tag'))],
            )
            outbounds_by_port.append({
                'port': port,
                'total_bytes': port_out_total,
                'nodes': port_nodes,
            })
        port_total_bytes = sum(item['total'] for item in ports)
        for item in ports:
            item['percent'] = round(item['total'] * 100 / port_total_bytes, 2) if port_total_bytes else 0
        ports.sort(key=lambda item: item['port'])
        outbounds_by_port.sort(key=lambda item: item['port'])
        port_totals = {int(item['port']): int(item['total']) for item in ports}
        xray_available = True
    except Exception as exc:
        xray_error = str(exc)

    ix_available = False
    ix_error = ''
    ix_user_started_at = xray_started_at
    user_totals = {}
    ix_users = previous_payload.get('ix_users', []) if isinstance(previous_payload.get('ix_users', []), list) else []
    ix_user_total_bytes = max(0, int(previous_payload.get('ix_user_total_bytes') or 0))
    managed_users = previous_payload.get('managed_users', []) if isinstance(previous_payload.get('managed_users', []), list) else []
    managed_user_total_bytes = max(0, int(previous_payload.get('managed_user_total_bytes') or 0))
    try:
        user_totals = parse_user_stats(query_stats('user>>>'))
        route_emails = ix_route_assignment_emails()
        ix_users = []
        managed_users = []
        for email, values in sorted(user_totals.items()):
            uplink = max(0, int(values.get('uplink', 0)))
            downlink = max(0, int(values.get('downlink', 0)))
            row = {'email': email, 'uplink': uplink, 'downlink': downlink, 'total': uplink + downlink}
            managed_users.append(row)
            if email in route_emails:
                ix_users.append(row)
        ix_user_total_bytes = sum(item['total'] for item in ix_users)
        managed_user_total_bytes = sum(item['total'] for item in managed_users)
        ix_available = True
    except Exception as exc:
        ix_error = str(exc)

    payload = dict(previous_payload)
    payload.update({
        'updated_at': int(time.time()),
        'available': xray_available,
        'reset_at': reset_at,
        'stats_since_at': reset_at,
        'xray_started_at': xray_started_at,
        'baseline_reset_at': baseline_reset_at,
        'baseline_stale': baseline_stale,
        'basis': basis,
        'total_bytes': total_bytes,
        'port_total_bytes': port_total_bytes,
        'nodes': nodes,
        'ports': ports,
        'outbounds_by_port': outbounds_by_port,
        'ix_available': ix_available,
        'ix_user_started_at': ix_user_started_at,
        'v2ray_started_at': ix_user_started_at,
        'ix_user_total_bytes': ix_user_total_bytes,
        'ix_users': ix_users,
        'managed_user_started_at': ix_user_started_at,
        'managed_user_total_bytes': managed_user_total_bytes,
        'managed_users': managed_users,
    })
    if xray_error:
        payload['error'] = xray_error
    else:
        payload.pop('error', None)
    if ix_error:
        payload['ix_error'] = ix_error
    else:
        payload.pop('ix_error', None)
    write_json(USAGE, payload)
    os.chmod(USAGE, 0o664)
    changes = sync_user_accounting(
        user_totals=user_totals,
        user_counter_epoch=ix_user_started_at,
        update_port_counters=ix_available,
        update_route_counters=ix_available,
    )
    runtime_ok = synchronize_runtime('用户额度结算与运行状态核对')
    print('OK: usage stats updated' if xray_available and ix_available else 'WARNING: usage stats partially unavailable')
    print('OUTBOUND_TOTAL_BYTES:', total_bytes)
    print('PORT_TOTAL_BYTES:', port_total_bytes)
    print('IX_USER_TOTAL_BYTES:', ix_user_total_bytes)
    if xray_error:
        print('XRAY_STATS_ERROR:', xray_error)
    if ix_error:
        print('XRAY_USER_STATS_ERROR:', ix_error)
    if changes:
        print('USER_STATUS_CHANGES:', ', '.join(f'{username}:{old}->{new}' for username, old, new in changes))
    return 0 if xray_available and ix_available and runtime_ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
