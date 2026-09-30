#!/usr/bin/env python3
import copy
import fcntl
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path('/opt/ixr-manager')
DATA = BASE / 'data'
USERS_DB = DATA / 'users.db'
STATE = DATA / 'state.json'
IX_LEGACY = DATA / 'ix_legacy.json'
XRAY_CONFIG = Path('/usr/local/etc/xray/config.json')
XRAY = '/usr/local/bin/xray'
SERVER = '127.0.0.1:10085'
LOCK_FILE = Path('/run/lock/ixr-runtime-sync.lock')
MANAGED_EMAIL_SUFFIX = '@ixr.local'
BLOCK_RULE_PREFIX = 'ixr-user-block-'


def read_json(path, default):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
        return value if value is not None else default
    except Exception:
        return default


def effective_user_status(row, used_bytes, now):
    if int(row['enabled'] or 0) != 1:
        return 'disabled'
    expires_at = str(row['expires_at'] or '').strip()
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at) <= now:
                return 'expired'
        except ValueError:
            pass
    limit = row['traffic_limit_bytes']
    if limit is not None and int(used_bytes) >= int(limit):
        return 'quota_exhausted'
    return 'active'


def state_protocols():
    state = read_json(STATE, {})
    protocols = {}
    for item in state.get('ports') or []:
        if not isinstance(item, dict):
            continue
        port = int(item.get('port') or 0)
        if port > 0:
            protocols[port] = str(item.get('protocol') or 'vmess')
    return protocols


def shared_inbound_details():
    legacy = read_json(IX_LEGACY, {})
    shared_tag = str(legacy.get('shared_tag') or 'mixed')
    shared_port = int(legacy.get('shared_port') or 10183)
    for inbound in legacy.get('inbounds') or []:
        if not isinstance(inbound, dict):
            continue
        tag = str(inbound.get('tag') or '')
        port = int(inbound.get('port') or 0)
        if tag == shared_tag or port == shared_port:
            return str(tag or shared_tag), str(inbound.get('protocol') or 'vmess')
    return shared_tag, 'vmess'


def load_assignments():
    if not USERS_DB.is_file():
        return []
    database = sqlite3.connect(f'file:{USERS_DB}?mode=ro', uri=True, timeout=10)
    database.row_factory = sqlite3.Row
    try:
        has_routes = bool(database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_routes'").fetchone())
        route_total_sql = "COALESCE((SELECT SUM(ur.traffic_used_bytes) FROM user_routes ur WHERE ur.user_id = u.id), 0)" if has_routes else '0'
        users = database.execute(
            f'''
            SELECT u.id, u.enabled, u.expires_at, u.traffic_limit_bytes,
                   COALESCE((SELECT SUM(up.traffic_used_bytes) FROM user_ports up WHERE up.user_id = u.id), 0)
                   + {route_total_sql} AS traffic_used_bytes
            FROM users u
            '''
        ).fetchall()
        port_columns = {str(row[1]) for row in database.execute('PRAGMA table_info(user_ports)')}
        required = {'uuid', 'xray_email'}
        if not required.issubset(port_columns):
            raise RuntimeError('IXR 共享端口数据库迁移尚未完成')
        port_rows = database.execute(
            'SELECT id, user_id, port, uuid, xray_email, active FROM user_ports ORDER BY id'
        ).fetchall()
        route_rows = database.execute(
            'SELECT id, user_id, uuid, xray_email, active FROM user_routes ORDER BY id'
        ).fetchall() if has_routes else []
    finally:
        database.close()

    now = datetime.now(timezone(timedelta(hours=8))).replace(tzinfo=None)
    statuses = {
        int(user['id']): effective_user_status(user, int(user['traffic_used_bytes'] or 0), now)
        for user in users
    }
    protocols = state_protocols()
    shared_tag, shared_protocol = shared_inbound_details()
    assignments = []
    for row in port_rows:
        email = str(row['xray_email'] or '').strip()
        credential_uuid = str(row['uuid'] or '').strip()
        if not email.lower().endswith(MANAGED_EMAIL_SUFFIX) or not credential_uuid:
            if int(row['active'] or 0) == 1:
                raise RuntimeError(f"IXR 端口授权 #{int(row['id'])} 的凭证不完整")
            continue
        port = int(row['port'])
        assignments.append({
            'kind': 'ixr',
            'assignment_id': int(row['id']),
            'user_id': int(row['user_id']),
            'tag': f'in-{port}',
            'protocol': protocols.get(port, 'vmess'),
            'uuid': credential_uuid,
            'email': email,
            'assigned': int(row['active'] or 0) == 1,
            'status': statuses.get(int(row['user_id']), 'disabled'),
        })
    for row in route_rows:
        email = str(row['xray_email'] or '').strip()
        credential_uuid = str(row['uuid'] or '').strip()
        if not email.lower().endswith(MANAGED_EMAIL_SUFFIX) or not credential_uuid:
            if int(row['active'] or 0) == 1:
                raise RuntimeError(f"IX 线路授权 #{int(row['id'])} 的凭证不完整")
            continue
        assignments.append({
            'kind': 'ix',
            'assignment_id': int(row['id']),
            'user_id': int(row['user_id']),
            'tag': shared_tag,
            'protocol': shared_protocol,
            'uuid': credential_uuid,
            'email': email,
            'assigned': int(row['active'] or 0) == 1,
            'status': statuses.get(int(row['user_id']), 'disabled'),
        })
    return assignments


def run_api(arguments, timeout=15):
    result = subprocess.run(
        [XRAY, 'api', *arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if result.returncode != 0:
        command = str(arguments[0] if arguments else 'unknown')
        raise RuntimeError(f'Xray API {command} 调用失败（退出码 {result.returncode}）')
    return result.stdout or ''


def parse_json_output(output):
    start = output.find('{')
    if start < 0:
        return {}
    return json.loads(output[start:])


def runtime_emails(tag):
    payload = parse_json_output(run_api(['inbounduser', f'--server={SERVER}', f'-tag={tag}']))
    emails = set()
    for user in payload.get('users') or []:
        if not isinstance(user, dict):
            continue
        email = str(user.get('email') or '').strip()
        if email:
            emails.add(email.lower())
    return emails


def runtime_block_rule_tags():
    payload = parse_json_output(run_api(['lsrules', f'--server={SERVER}']))
    tags = set()
    for rule in payload.get('rules') or []:
        if not isinstance(rule, dict):
            continue
        tag = str(rule.get('ruleTag') or '')
        if tag.startswith(BLOCK_RULE_PREFIX):
            tags.add(tag)
    return tags


def block_rule(assignment):
    rule_tag = f"{BLOCK_RULE_PREFIX}{assignment['kind']}-{int(assignment['assignment_id'])}"
    return {
        'type': 'field',
        'inboundTag': [assignment['tag']],
        'user': [assignment['email']],
        'outboundTag': 'block',
        'ruleTag': rule_tag,
    }


def temporary_json(payload):
    handle = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', prefix='ixr-runtime-', suffix='.json', delete=False)
    try:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
        handle.flush()
        os.fchmod(handle.fileno(), 0o600)
        return Path(handle.name)
    finally:
        handle.close()


def reload_routing(blocked_assignments):
    config = read_json(XRAY_CONFIG, {})
    routing = copy.deepcopy(config.get('routing') or {})
    rules = [
        rule for rule in routing.get('rules') or []
        if not (isinstance(rule, dict) and str(rule.get('ruleTag') or '').startswith(BLOCK_RULE_PREFIX))
    ]
    routing['rules'] = [block_rule(item) for item in blocked_assignments] + rules
    path = temporary_json({'routing': routing})
    try:
        run_api(['adrules', f'--server={SERVER}', str(path)], timeout=30)
    finally:
        path.unlink(missing_ok=True)


def remove_users(tag, emails):
    if not emails:
        return
    run_api(['rmu', f'--server={SERVER}', f'-tag={tag}', *sorted(emails)], timeout=30)


def add_users(tag, protocol, assignments):
    if not assignments:
        return
    clients = [
        {
            'id': item['uuid'],
            'alterId': 0,
            'email': item['email'],
            'level': 0,
        }
        for item in assignments
    ]
    path = temporary_json({
        'inbounds': [{
            'tag': tag,
            'protocol': protocol,
            'settings': {'clients': clients},
        }],
    })
    try:
        run_api(['adu', f'--server={SERVER}', str(path)], timeout=30)
    finally:
        path.unlink(missing_ok=True)


def synchronize():
    assignments = load_assignments()
    active = [item for item in assignments if item['assigned'] and item['status'] == 'active']
    blocked = [item for item in assignments if item['assigned'] and item['status'] != 'active']
    desired_block_tags = {block_rule(item)['ruleTag'] for item in blocked}
    current_block_tags = runtime_block_rule_tags()
    routing_changed = desired_block_tags != current_block_tags
    if routing_changed:
        reload_routing(blocked)

    managed_by_tag = {}
    active_by_tag = {}
    protocol_by_tag = {}
    for item in assignments:
        managed_by_tag.setdefault(item['tag'], set()).add(item['email'].lower())
        protocol_by_tag[item['tag']] = item['protocol']
    for item in active:
        active_by_tag.setdefault(item['tag'], {})[item['email'].lower()] = item

    removed = 0
    added = 0
    for tag, managed_emails in managed_by_tag.items():
        desired = active_by_tag.get(tag, {})
        try:
            current = runtime_emails(tag)
        except Exception:
            if desired:
                raise
            continue
        remove_set = (current & managed_emails) - set(desired)
        if remove_set:
            remove_users(tag, remove_set)
            removed += len(remove_set)
        add_items = [item for email, item in desired.items() if email not in current]
        if add_items:
            add_users(tag, protocol_by_tag.get(tag, 'vmess'), add_items)
            added += len(add_items)

    for tag, managed_emails in managed_by_tag.items():
        desired = active_by_tag.get(tag, {})
        try:
            current = runtime_emails(tag)
        except Exception:
            if desired:
                raise
            continue
        missing = set(desired) - current
        forbidden = (current & managed_emails) - set(desired)
        if missing or forbidden:
            raise RuntimeError(f'Xray 入站 {tag} 的用户状态未收敛')
    return {
        'active': len(active),
        'blocked': len(blocked),
        'added': added,
        'removed': removed,
        'routing_changed': routing_changed,
    }


class runtime_lock:
    def __enter__(self):
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        self.handle = os.fdopen(descriptor, 'r+')
        fcntl.flock(self.handle, fcntl.LOCK_EX)
        return self.handle

    def __exit__(self, exc_type, exc, traceback):
        fcntl.flock(self.handle, fcntl.LOCK_UN)
        self.handle.close()


def main():
    try:
        with runtime_lock():
            result = synchronize()
    except Exception as exc:
        print(f'ERROR: Xray 用户动态收敛失败：{exc}', file=sys.stderr)
        return 1
    changed = int(result['added']) + int(result['removed'])
    print(
        'OK: Xray 用户动态收敛完成; '
        f"active={result['active']} blocked={result['blocked']} changed={changed} "
        f"routing_changed={1 if result['routing_changed'] else 0}"
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
