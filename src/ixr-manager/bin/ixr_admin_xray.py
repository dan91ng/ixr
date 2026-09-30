#!/usr/bin/env python3
import base64
import copy
import fcntl
import grp
import json
import os
import pwd
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DATA = Path(os.environ.get('IXR_ADMIN_DATA', '/opt/ixr-manager/data'))
OUTBOUNDS = Path(os.environ.get('IXR_ADMIN_OUTBOUNDS', str(DATA / 'outbounds.json')))
STATE = Path(os.environ.get('IXR_ADMIN_STATE', str(DATA / 'state.json')))
IX_LEGACY = Path(os.environ.get('IXR_ADMIN_IX_LEGACY', str(DATA / 'ix_legacy.json')))
IX_ROUTES = Path(os.environ.get('IXR_ADMIN_IX_ROUTES', str(DATA / 'ix_routes.json')))
USERS_DB = Path(os.environ.get('IXR_ADMIN_USERS_DB', str(DATA / 'users.db')))
APPLY_ASYNC = os.environ.get('IXR_ADMIN_APPLY_ASYNC', '/usr/local/bin/ixr-admin-apply')
LOCK_FILE = Path(os.environ.get('IXR_ADMIN_LOCK', '/run/lock/ixr-admin-xray.lock'))
VISIBILITY_FILE = Path(os.environ.get('IXR_ADMIN_VISIBILITY', '/var/lib/v2ray-panel/node_visibility.json'))
FRONT_HOST_FILE = Path(os.environ.get('IXR_ADMIN_FRONT_HOST', '/var/lib/v2ray-panel/front_entry_host'))
NODE_IP_CACHE = Path(os.environ.get('IXR_ADMIN_NODE_IP_CACHE', '/tmp/v2ray_node_ips.json'))
MANAGED_EMAIL_SUFFIX = '@ixr.local'
SHARED_TAG = 'mixed'
DEFAULT_SHARED_PORT = 10183


def read_json(path, default=None):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
        return value if value is not None else default
    except Exception:
        return default


def read_required_json(path, label):
    source = Path(path)
    try:
        payload = source.read_text(encoding='utf-8')
    except FileNotFoundError as exc:
        raise RuntimeError(f'{label}不存在') from exc
    except OSError as exc:
        raise RuntimeError(f'{label}读取失败：{exc}') from exc
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'{label}不是有效 JSON：第 {exc.lineno} 行') from exc


def file_profile(path, default_mode, default_user, default_group):
    if path.exists():
        stat = path.stat()
        return stat.st_mode & 0o777, stat.st_uid, stat.st_gid
    return default_mode, pwd.getpwnam(default_user).pw_uid, grp.getgrnam(default_group).gr_gid


def atomic_write_bytes(path, payload, mode, uid, gid):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, value, profile):
    payload = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    atomic_write_bytes(path, payload, *profile)


def write_text(path, value, profile):
    atomic_write_bytes(path, (str(value).strip() + '\n').encode('utf-8'), *profile)


def snapshot_files(paths):
    snapshot = {}
    for path in paths:
        if path.exists():
            stat = path.stat()
            snapshot[path] = (path.read_bytes(), stat.st_mode & 0o777, stat.st_uid, stat.st_gid)
        else:
            snapshot[path] = None
    return snapshot


def restore_files(snapshot):
    for path, item in snapshot.items():
        if item is None:
            path.unlink(missing_ok=True)
            continue
        payload, mode, uid, gid = item
        atomic_write_bytes(path, payload, mode, uid, gid)


def snapshot_database():
    if not USERS_DB.is_file():
        return None
    stat = USERS_DB.stat()
    descriptor, name = tempfile.mkstemp(prefix='ixr-admin-users-', suffix='.db')
    os.close(descriptor)
    path = Path(name)
    source = sqlite3.connect(USERS_DB, timeout=30)
    target = sqlite3.connect(path, timeout=30)
    try:
        source.backup(target)
        target.commit()
    finally:
        target.close()
        source.close()
    os.chmod(path, 0o600)
    return path, stat.st_mode & 0o777, stat.st_uid, stat.st_gid


def restore_database(snapshot):
    if snapshot is None:
        return
    path, mode, uid, gid = snapshot
    source = sqlite3.connect(path, timeout=30)
    target = sqlite3.connect(USERS_DB, timeout=30)
    try:
        source.backup(target)
        target.commit()
        target.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    finally:
        target.close()
        source.close()
    os.chmod(USERS_DB, mode)
    os.chown(USERS_DB, uid, gid)


def cleanup_database_snapshot(snapshot):
    if snapshot is not None:
        snapshot[0].unlink(missing_ok=True)


def safe_tag(name):
    value = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(name or '')).strip('-')
    return value or 'node'


def validate_name(value):
    name = str(value or '').strip()
    if not name or not re.fullmatch(r'[A-Za-z0-9_-]+', name):
        raise RuntimeError('标签只能包含字母、数字、下划线和中划线')
    return name


def validate_existing_name(value):
    name = str(value or '').strip()
    if not name or len(name) > 200 or any(ord(character) < 32 for character in name):
        raise RuntimeError('出口名称无效')
    return name


def validate_address(value):
    address = str(value or '').strip()
    if not address or re.search(r'\s', address):
        raise RuntimeError('落地地址不能为空，且不能包含空格')
    return address


def validate_port(value, label='端口'):
    try:
        port = int(value)
    except Exception:
        port = 0
    if port <= 0 or port > 65535:
        raise RuntimeError(f'{label}必须在 1-65535 之间')
    return port


def validate_uuid(value, label='UUID'):
    text = str(value or '').strip()
    try:
        parsed = uuid.UUID(text)
    except Exception as exc:
        raise RuntimeError(f'{label}格式不正确') from exc
    return str(parsed)


def input_value(input_data, default, *keys):
    for key in keys:
        if key in input_data:
            return input_data.get(key)
    return default


def input_bool(input_data, key, default=False):
    if key not in input_data:
        return bool(default)
    value = input_data.get(key)
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'on'}
    return bool(value)


def front_host():
    stored = FRONT_HOST_FILE.read_text(encoding='utf-8').strip() if FRONT_HOST_FILE.is_file() else ''
    return stored or os.environ.get('IX_PANEL_FRONT_ENTRY_HOST', '').strip() or 'public.cloudc.dev'


def normalize_front_host(value):
    host = str(value or '').strip()
    host = re.sub(r'^[A-Za-z][A-Za-z0-9+.-]*://', '', host)
    host = re.sub(r'[/#?].*$', '', host).strip(' []')
    if host.count(':') == 1 and re.fullmatch(r'.+:\d+', host):
        host = host.rsplit(':', 1)[0]
    if not host or len(host) > 255 or not re.fullmatch(r'[A-Za-z0-9._:-]+', host):
        raise RuntimeError('连接地址只能填写有效域名或 IP')
    return host


def load_canonical():
    outbounds = read_required_json(OUTBOUNDS, 'IXR 出口目录')
    state = read_required_json(STATE, 'IXR 状态文件')
    legacy = read_required_json(IX_LEGACY, 'IX 迁移配置')
    routes = read_required_json(IX_ROUTES, 'IX 线路目录')
    if not isinstance(outbounds, list):
        raise RuntimeError('IXR 出口目录格式错误')
    if not isinstance(state, dict):
        raise RuntimeError('IXR 状态文件格式错误')
    if not isinstance(legacy, dict) or int(legacy.get('version') or 0) != 1:
        raise RuntimeError('IX 迁移配置格式错误')
    if not isinstance(routes, dict):
        raise RuntimeError('IX 线路目录格式错误')
    state.setdefault('ports', [])
    state.setdefault('smart_pools', [])
    legacy.setdefault('inbounds', [])
    legacy.setdefault('legacy_routes', [])
    routes.setdefault('version', 1)
    routes.setdefault('routes', [])
    if not isinstance(state['ports'], list) or not isinstance(state['smart_pools'], list):
        raise RuntimeError('IXR 状态列表格式错误')
    if not isinstance(legacy['inbounds'], list) or not isinstance(legacy['legacy_routes'], list):
        raise RuntimeError('IX 迁移列表格式错误')
    if not isinstance(routes['routes'], list):
        raise RuntimeError('IX 线路目录列表格式错误')
    return outbounds, state, legacy, routes


def shared_inbound(legacy):
    shared_port = int(legacy.get('shared_port') or DEFAULT_SHARED_PORT)
    for inbound in legacy.get('inbounds') or []:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get('tag') or '') == str(legacy.get('shared_tag') or SHARED_TAG) or int(inbound.get('port') or 0) == shared_port:
            settings = inbound.setdefault('settings', {})
            clients = settings.get('clients')
            if not isinstance(clients, list):
                settings['clients'] = []
            return inbound
    raise RuntimeError('IX 共享入站不存在')


def outbound_by_name(outbounds, name):
    for item in outbounds:
        if isinstance(item, dict) and str(item.get('name') or '') == name:
            return item
    return None


def route_by_code(routes, route_code):
    for item in routes.get('routes') or []:
        if isinstance(item, dict) and str(item.get('route_code') or '') == route_code:
            return item
    return None


def route_assignments(route_code, outbound_tag):
    if not USERS_DB.is_file():
        return 0
    database = sqlite3.connect(f'file:{USERS_DB}?mode=ro', uri=True, timeout=10)
    try:
        has_routes = bool(database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_routes'").fetchone())
        if not has_routes:
            return 0
        row = database.execute(
            'SELECT COUNT(*) FROM user_routes WHERE active = 1 AND (route_code = ? OR outbound_tag IN (?, ?))',
            (route_code, route_code, outbound_tag),
        ).fetchone()
        return int(row[0] or 0)
    finally:
        database.close()


def deactivate_route_assignments(route_code, outbound_tag):
    if not USERS_DB.is_file():
        return 0
    database = sqlite3.connect(USERS_DB, timeout=30)
    database.execute('PRAGMA foreign_keys = ON')
    database.execute('PRAGMA busy_timeout = 30000')
    now_text = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        database.execute('BEGIN IMMEDIATE')
        has_routes = bool(database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_routes'").fetchone())
        if not has_routes:
            database.commit()
            return 0
        cursor = database.execute(
            '''
            UPDATE user_routes
            SET active = 0, unassigned_at = COALESCE(unassigned_at, ?), updated_at = ?
            WHERE active = 1 AND (route_code = ? OR outbound_tag IN (?, ?))
            ''',
            (now_text, now_text, route_code, route_code, outbound_tag),
        )
        count = max(0, int(cursor.rowcount or 0))
        has_audit = bool(database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_logs'").fetchone())
        if has_audit and count:
            database.execute(
                '''
                INSERT INTO audit_logs(actor, action, target_type, target_id, details_json, success, created_at)
                VALUES ('ix-admin', 'route_assignments_deactivated', 'ix_route', NULL, ?, 1, ?)
                ''',
                (json.dumps({'route_code': route_code, 'assignments': count}, ensure_ascii=False), now_text),
            )
        database.commit()
        return count
    except Exception:
        database.rollback()
        raise
    finally:
        database.close()


def route_network(legacy):
    inbound = shared_inbound(legacy)
    return str((inbound.get('streamSettings') or {}).get('network') or 'tcp')


def next_probe_port(outbounds, state, legacy):
    used = {10085, 10185, 10198, 10199}
    for item in outbounds:
        if isinstance(item, dict):
            try:
                used.add(int(item.get('probe_port') or item.get('port') or 0))
            except Exception:
                pass
    for item in state.get('ports') or []:
        if isinstance(item, dict):
            try:
                used.add(int(item.get('port') or 0))
            except Exception:
                pass
    for item in legacy.get('inbounds') or []:
        if isinstance(item, dict):
            try:
                used.add(int(item.get('port') or 0))
            except Exception:
                pass
    for port in range(31200, 32000):
        if port not in used:
            return port
    raise RuntimeError('没有可用的 Xray 本地探测端口')


def normalize_managed_outbound(item):
    name = validate_name(item.get('name'))
    address = validate_address(item.get('address'))
    remote_port = validate_port(item.get('remote_port') or item.get('server_port'), '远端端口')
    probe_port = validate_port(item.get('probe_port') or item.get('port'), '本地探测端口')
    user_id = validate_uuid(item.get('id') or item.get('uuid'), '落地节点 UUID')
    return {
        'name': name,
        'protocol': 'vmess',
        'address': address,
        'remote_port': remote_port,
        'id': user_id,
        'aid': int(item.get('aid') or item.get('alterId') or 0),
        'security': str(item.get('security') or item.get('scy') or 'auto').strip() or 'auto',
        'network': str(item.get('network') or item.get('net') or 'tcp').strip() or 'tcp',
        'header_type': str(item.get('header_type') or item.get('type') or 'none').strip() or 'none',
        'host': str(item.get('host') or '').strip(),
        'path': str(item.get('path') or '').strip(),
        'tls': str(item.get('tls') or '').strip(),
        'sni': str(item.get('sni') or '').strip(),
        'alpn': str(item.get('alpn') or '').strip(),
        'fp': str(item.get('fp') or item.get('fingerprint') or '').strip(),
        'insecure': str(item.get('insecure') or '0').strip(),
        'probe_port': probe_port,
        'port': probe_port,
        'kind': 'vmess',
        'tag': 'via-' + safe_tag(name),
    }


def add_legacy_ix_binding(legacy, route_code):
    shared = shared_inbound(legacy)
    clients = (shared.get('settings') or {}).get('clients') or []
    used_emails = {str(item.get('email') or '') for item in clients if isinstance(item, dict)}
    email_base = safe_tag(route_code).lower() or 'ix-node'
    email = email_base + '@v2ray.com'
    if email in used_emails:
        email = f'{email_base}-{int(time.time())}@v2ray.com'
    clients.append({'id': str(uuid.uuid4()), 'level': 0, 'email': email})
    legacy['legacy_routes'].append({'email': email, 'route_code': route_code})
    return email


def remove_legacy_ix_bindings(legacy, route_codes):
    route_codes = {str(item) for item in route_codes if str(item)}
    removed_emails = {
        str(item.get('email') or '')
        for item in legacy.get('legacy_routes') or []
        if isinstance(item, dict) and str(item.get('route_code') or '') in route_codes
    }
    legacy['legacy_routes'] = [
        item for item in legacy.get('legacy_routes') or []
        if not (isinstance(item, dict) and str(item.get('route_code') or '') in route_codes)
    ]
    still_used = {
        str(item.get('email') or '')
        for item in legacy.get('legacy_routes') or []
        if isinstance(item, dict)
    }
    shared = shared_inbound(legacy)
    shared['settings']['clients'] = [
        client for client in (shared.get('settings') or {}).get('clients') or []
        if not (isinstance(client, dict) and str(client.get('email') or '') in removed_emails - still_used)
    ]
    return len(removed_emails)


def update_state_references(state, old_name, new_name=None):
    for pool in state.get('smart_pools') or []:
        if not isinstance(pool, dict):
            continue
        members = [str(item) for item in pool.get('members') or []]
        if new_name is None:
            pool['members'] = [item for item in members if item != old_name]
        else:
            pool['members'] = list(dict.fromkeys(new_name if item == old_name else item for item in members))
    for port_config in state.get('ports') or []:
        if not isinstance(port_config, dict):
            continue
        retained = []
        for rule in port_config.get('rules') or []:
            if not isinstance(rule, dict):
                continue
            if str(rule.get('outbound') or '') == old_name:
                if new_name is None:
                    continue
                rule['outbound'] = new_name
            retained.append(rule)
        port_config['rules'] = retained


def add_dn42_member(state, name):
    if 'DN42' not in name.upper():
        return
    for pool in state.get('smart_pools') or []:
        if not isinstance(pool, dict):
            continue
        if str(pool.get('id') or '') == 'dn42' or str(pool.get('name') or '') == 'DN42智能自动':
            members = [str(item) for item in pool.get('members') or []]
            if name not in members:
                members.append(name)
            pool['members'] = members


def read_visibility():
    value = read_json(VISIBILITY_FILE, {})
    return value if isinstance(value, dict) else {}


def write_visibility(value):
    profile = file_profile(VISIBILITY_FILE, 0o600, 'www-data', 'www-data')
    write_json(VISIBILITY_FILE, value, profile)


def write_canonical(outbounds, state, legacy, routes):
    profiles = {
        OUTBOUNDS: file_profile(OUTBOUNDS, 0o664, 'www-data', 'www-data'),
        STATE: file_profile(STATE, 0o664, 'www-data', 'www-data'),
        IX_LEGACY: file_profile(IX_LEGACY, 0o600, 'root', 'root'),
        IX_ROUTES: file_profile(IX_ROUTES, 0o640, 'root', 'www-data'),
    }
    write_json(OUTBOUNDS, outbounds, profiles[OUTBOUNDS])
    write_json(STATE, state, profiles[STATE])
    write_json(IX_LEGACY, legacy, profiles[IX_LEGACY])
    write_json(IX_ROUTES, routes, profiles[IX_ROUTES])


def apply_xray(reason):
    result = subprocess.run(
        [APPLY_ASYNC, str(reason)[:300]],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
    )
    if result.returncode != 0:
        output = (result.stdout or '').replace('\n', ' | ')[-1600:]
        raise RuntimeError(f'Xray 应用失败（{result.returncode}）：{output}')


def mutate_and_apply(reason, mutator, database_mutator=None):
    paths = [OUTBOUNDS, STATE, IX_LEGACY, IX_ROUTES, VISIBILITY_FILE]
    snapshot = snapshot_files(paths)
    database_snapshot = snapshot_database() if database_mutator is not None else None
    outbounds, state, legacy, routes = load_canonical()
    canonical_written = False
    try:
        result = mutator(outbounds, state, legacy, routes)
        if database_mutator is not None:
            database_mutator(result)
        write_canonical(outbounds, state, legacy, routes)
        canonical_written = True
        apply_xray(reason)
    except Exception:
        restore_files(snapshot)
        if database_snapshot is not None:
            restore_database(database_snapshot)
        if canonical_written or database_snapshot is not None:
            try:
                apply_xray('IX Admin 失败自动恢复')
            except Exception as recovery_error:
                raise RuntimeError(f'修改失败且自动恢复 Xray 失败：{recovery_error}')
        raise
    finally:
        cleanup_database_snapshot(database_snapshot)
    return result


def route_entry(name, outbound, legacy):
    return {
        'route_code': name,
        'display_name': name,
        'outbound_tag': str(outbound.get('tag') or ('via-' + safe_tag(name))),
        'address': front_host(),
        'port': int(legacy.get('shared_port') or DEFAULT_SHARED_PORT),
        'protocol': 'vmess',
        'network': route_network(legacy),
    }


def tcp_latency(address, port):
    started = time.monotonic()
    try:
        with socket.create_connection((address, int(port)), timeout=1.5):
            return f'{int((time.monotonic() - started) * 1000)}ms'
    except Exception:
        return '超时'


def resolve_ip(address):
    try:
        return address if socket.inet_aton(address) else address
    except OSError:
        try:
            return socket.gethostbyname(address)
        except Exception:
            return ''


def xray_stream(item):
    network = str(item.get('network') or 'tcp')
    stream = {'network': network}
    if network == 'ws':
        settings = {}
        if item.get('path'):
            settings['path'] = item['path']
        if item.get('host'):
            settings['headers'] = {'Host': item['host']}
        stream['wsSettings'] = settings
    elif network == 'grpc':
        stream['grpcSettings'] = {'serviceName': str(item.get('path') or '').lstrip('/') or str(item.get('host') or '')}
    else:
        stream['tcpSettings'] = {'header': {'type': str(item.get('header_type') or 'none')}}
    if item.get('tls'):
        stream['security'] = item['tls']
    return stream


def panel_data():
    outbounds, _state, legacy, routes = load_canonical()
    shared = shared_inbound(legacy)
    clients = [copy.deepcopy(item) for item in (shared.get('settings') or {}).get('clients') or [] if isinstance(item, dict)]
    clients = [item for item in clients if not str(item.get('email') or '').lower().endswith(MANAGED_EMAIL_SUFFIX)]
    clients_by_email = {str(item.get('email') or ''): str(item.get('id') or '') for item in clients}
    bindings = {
        str(item.get('route_code') or ''): str(item.get('email') or '')
        for item in legacy.get('legacy_routes') or []
        if isinstance(item, dict) and item.get('route_code') and item.get('email')
    }
    visibility = read_visibility()
    exit_ips = read_json(NODE_IP_CACHE, {})
    exit_ips = exit_ips if isinstance(exit_ips, dict) else {}
    warnings = []
    route_map = {}
    for route in routes.get('routes') or []:
        if not isinstance(route, dict):
            continue
        name = str(route.get('route_code') or '').strip()
        if name:
            route_map[name] = route
            if outbound_by_name(outbounds, name) is None:
                warnings.append(f'{name} 缺少 Xray 出口')

    managed_outbounds = []
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        name = str(outbound.get('name') or '').strip()
        if not name:
            warnings.append('存在缺少名称的 Xray 出口')
            continue
        managed_outbounds.append((name, outbound))

    def measure_latency(item):
        name, outbound = item
        return name, tcp_latency(str(outbound.get('address') or ''), int(outbound.get('remote_port') or 0))

    latencies = {}
    if managed_outbounds:
        with ThreadPoolExecutor(max_workers=min(10, len(managed_outbounds))) as executor:
            latencies = dict(executor.map(measure_latency, managed_outbounds))

    nodes = []
    for name, outbound in managed_outbounds:
        address = str(outbound.get('address') or '')
        remote_port = int(outbound.get('remote_port') or 0)
        landing_ip = resolve_ip(address)
        exit_ip = str(exit_ips.get(name) or exit_ips.get(outbound.get('tag')) or '待探测 (点击右上角)')
        if landing_ip and re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', exit_ip):
            probe_result = '一致' if landing_ip == exit_ip else '不一致'
        elif not landing_ip:
            probe_result = '解析失败'
        else:
            probe_result = '待探测'
        is_ix_route = name in route_map
        frontend_email = bindings.get(name, '') if is_ix_route else ''
        nodes.append({
            'tag': name,
            'protocol': str(outbound.get('protocol') or 'vmess'),
            'settings': {'vnext': [{'address': address, 'port': remote_port, 'users': [{'id': str(outbound.get('id') or ''), 'alterId': int(outbound.get('aid') or 0), 'security': str(outbound.get('security') or 'auto')}]}]},
            'streamSettings': xray_stream(outbound),
            'config_ip': address,
            'landing_ip': landing_ip,
            'config_port': remote_port,
            'latency': latencies.get(name, '超时'),
            'exit_ip': exit_ip,
            'probe_result': probe_result,
            'uuid': str(outbound.get('id') or ''),
            'probe_port': int(outbound.get('probe_port') or outbound.get('port') or 0),
            'aid': int(outbound.get('aid') or 0),
            'security': str(outbound.get('security') or 'auto'),
            'network': str(outbound.get('network') or 'tcp'),
            'header_type': str(outbound.get('header_type') or 'none'),
            'host': str(outbound.get('host') or ''),
            'path': str(outbound.get('path') or ''),
            'tls': str(outbound.get('tls') or ''),
            'sni': str(outbound.get('sni') or ''),
            'alpn': str(outbound.get('alpn') or ''),
            'fp': str(outbound.get('fp') or ''),
            'insecure': str(outbound.get('insecure') or '0'),
            'is_ix_route': is_ix_route,
            'frontend_email': frontend_email,
            'frontend_uuid': clients_by_email.get(frontend_email, ''),
            'show_on_front': is_ix_route and visibility.get(name, True) is not False,
        })
    ix_route_count = sum(1 for node in nodes if node['is_ix_route'])
    return {
        'success': True,
        'clients': clients,
        'nodes': nodes,
        'bindings': bindings,
        'outbound_count': len(nodes),
        'ix_route_count': ix_route_count,
        'ixr_only_count': len(nodes) - ix_route_count,
        'inbound_port': int(legacy.get('shared_port') or DEFAULT_SHARED_PORT),
        'front_entry_host': front_host(),
        'warnings': warnings,
        'backend': 'xray',
    }


def edit_node(input_data):
    old_name = validate_name(input_data.get('old_tag'))

    def mutation(outbounds, state, legacy, routes):
        outbound = outbound_by_name(outbounds, old_name)
        if outbound is None:
            raise RuntimeError('未找到对应的出口节点')
        route = route_by_code(routes, old_name)
        was_ix_route = route is not None
        new_name = validate_name(input_value(input_data, old_name, 'name', 'new_tag'))
        address = validate_address(input_value(input_data, outbound.get('address'), 'address', 'new_address'))
        remote_port = validate_port(input_value(input_data, outbound.get('remote_port'), 'remote_port', 'new_port'), '远端端口')
        user_id = validate_uuid(input_value(input_data, outbound.get('id'), 'id', 'new_uuid'), '落地节点 UUID')
        probe_port = validate_port(input_value(input_data, outbound.get('probe_port') or outbound.get('port'), 'probe_port'), '本地探测端口')
        enable_ix = input_bool(input_data, 'enable_ix', was_ix_route)
        visibility = read_visibility()
        show_on_front = input_bool(input_data, 'show_on_front', visibility.get(old_name, True))
        if new_name != old_name and outbound_by_name(outbounds, new_name) is not None:
            raise RuntimeError('新标签名称已存在')
        if new_name != old_name and route_by_code(routes, new_name) is not None:
            raise RuntimeError('新标签已被 IX 线路目录使用')
        old_tag = str(outbound.get('tag') or ('via-' + safe_tag(old_name)))
        assignment_count = route_assignments(old_name, old_tag)
        if new_name != old_name and assignment_count > 0:
            raise RuntimeError('该线路仍分配给 IXR 用户，请先在用户管理中解除分配后再改名')
        if was_ix_route and not enable_ix and assignment_count > 0:
            raise RuntimeError('该线路仍分配给用户，请先在用户管理中解除分配后再改为 IXR 专用')
        normalized = normalize_managed_outbound({
            'name': new_name,
            'address': address,
            'remote_port': remote_port,
            'id': user_id,
            'aid': input_value(input_data, outbound.get('aid') or 0, 'aid'),
            'security': input_value(input_data, outbound.get('security') or 'auto', 'security'),
            'network': input_value(input_data, outbound.get('network') or 'tcp', 'network'),
            'header_type': input_value(input_data, outbound.get('header_type') or 'none', 'header_type'),
            'host': input_value(input_data, outbound.get('host') or '', 'host'),
            'path': input_value(input_data, outbound.get('path') or '', 'path'),
            'tls': input_value(input_data, outbound.get('tls') or '', 'tls'),
            'sni': input_value(input_data, outbound.get('sni') or '', 'sni'),
            'alpn': input_value(input_data, outbound.get('alpn') or '', 'alpn'),
            'fp': input_value(input_data, outbound.get('fp') or '', 'fp'),
            'insecure': input_value(input_data, outbound.get('insecure') or '0', 'insecure'),
            'probe_port': probe_port,
        })
        outbound.clear()
        outbound.update(normalized)
        if was_ix_route and enable_ix:
            route.update(route_entry(new_name, outbound, legacy))
            for item in legacy.get('legacy_routes') or []:
                if isinstance(item, dict) and str(item.get('route_code') or '') == old_name:
                    item['route_code'] = new_name
        elif was_ix_route:
            remove_legacy_ix_bindings(legacy, {old_name})
            routes['routes'] = [
                item for item in routes.get('routes') or []
                if not (isinstance(item, dict) and str(item.get('route_code') or '') == old_name)
            ]
        elif enable_ix:
            add_legacy_ix_binding(legacy, new_name)
            routes['routes'].append(route_entry(new_name, outbound, legacy))
        if new_name != old_name:
            update_state_references(state, old_name, new_name)
        add_dn42_member(state, new_name)
        if new_name != old_name:
            visibility.pop(old_name, None)
        if enable_ix:
            visibility[new_name] = show_on_front
        else:
            visibility.pop(new_name, None)
        write_visibility(visibility)
        node_type = 'IX 线路' if enable_ix else 'IXR 专用出口'
        return {'success': True, 'message': f'{node_type}信息已更新并同步到 Xray'}

    return mutate_and_apply(f'更新统一出口 {old_name}', mutation)


def create_node(input_data):
    def mutation(outbounds, state, legacy, routes):
        probe_value = input_value(input_data, 0, 'probe_port')
        try:
            probe_port = int(probe_value or 0)
        except Exception:
            probe_port = 0
        if probe_port <= 0:
            probe_port = next_probe_port(outbounds, state, legacy)
        outbound = normalize_managed_outbound({
            'name': input_value(input_data, '', 'name', 'new_tag'),
            'address': input_value(input_data, '', 'address', 'new_address'),
            'remote_port': input_value(input_data, 0, 'remote_port', 'new_port'),
            'id': input_value(input_data, '', 'id', 'new_uuid'),
            'aid': input_value(input_data, 0, 'aid'),
            'security': input_value(input_data, 'auto', 'security'),
            'network': input_value(input_data, 'tcp', 'network'),
            'header_type': input_value(input_data, 'none', 'header_type'),
            'host': input_value(input_data, '', 'host'),
            'path': input_value(input_data, '', 'path'),
            'tls': input_value(input_data, '', 'tls'),
            'sni': input_value(input_data, '', 'sni'),
            'alpn': input_value(input_data, '', 'alpn'),
            'fp': input_value(input_data, '', 'fp'),
            'insecure': input_value(input_data, '0', 'insecure'),
            'probe_port': probe_port,
        })
        name = outbound['name']
        if outbound_by_name(outbounds, name) is not None or route_by_code(routes, name) is not None:
            raise RuntimeError('节点标签已经存在')
        enable_ix = input_bool(input_data, 'enable_ix', True)
        outbounds.append(outbound)
        if enable_ix:
            add_legacy_ix_binding(legacy, name)
            routes['routes'].append(route_entry(name, outbound, legacy))
            visibility = read_visibility()
            visibility[name] = input_bool(input_data, 'show_on_front', True)
            write_visibility(visibility)
        add_dn42_member(state, name)
        node_type = 'IX 线路' if enable_ix else 'IXR 专用出口'
        return {'success': True, 'message': f'{node_type}已新增并同步到 Xray', 'tag': name}

    return mutate_and_apply('新增统一出口', mutation)


def update_binding(input_data):
    route_code = validate_name(input_data.get('tag'))
    email = str(input_data.get('email') or '').strip()

    def mutation(outbounds, state, legacy, routes):
        if route_by_code(routes, route_code) is None or outbound_by_name(outbounds, route_code) is None:
            raise RuntimeError('未找到对应的 IX 线路')
        clients = (shared_inbound(legacy).get('settings') or {}).get('clients') or []
        available = {str(item.get('email') or '') for item in clients if isinstance(item, dict)}
        if email and email not in available:
            raise RuntimeError('选择的前端用户不存在')
        retained = [
            item for item in legacy.get('legacy_routes') or []
            if not (isinstance(item, dict) and str(item.get('route_code') or '') == route_code)
        ]
        if email:
            retained.append({'email': email, 'route_code': route_code})
        legacy['legacy_routes'] = retained
        return {'success': True, 'message': '路由调度已更新并同步到 Xray'}

    return mutate_and_apply(f'IX Admin 更新线路绑定 {route_code}', mutation)


def edit_client_uuid(input_data):
    email = str(input_data.get('email') or '').strip()
    user_id = validate_uuid(input_data.get('new_uuid') or str(uuid.uuid4()), '前端用户 UUID')
    if not email:
        raise RuntimeError('邮箱标识不能为空')

    def mutation(outbounds, state, legacy, routes):
        found = False
        clients = (shared_inbound(legacy).get('settings') or {}).get('clients') or []
        for client in clients:
            if isinstance(client, dict) and str(client.get('email') or '') == email:
                client['id'] = user_id
                client.setdefault('level', 0)
                found = True
                break
        if not found:
            raise RuntimeError('未找到对应的前端用户')
        return {'success': True, 'message': '前端用户 UUID 已更新并同步到 Xray'}

    return mutate_and_apply(f'IX Admin 更新旧 IX 凭证 {email}', mutation)


def parse_vmess_uri(uri, probe_port):
    text = str(uri or '').strip()
    if not text.startswith('vmess://'):
        raise RuntimeError('无效的 VMess 链接')
    encoded = text[8:].strip()
    encoded += '=' * (-len(encoded) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode()).decode('utf-8'))
    except Exception as exc:
        raise RuntimeError('VMess 链接解析失败') from exc
    raw_name = str(payload.get('ps') or f'node_{int(time.time())}')
    name = re.sub(r'[^A-Za-z0-9_-]+', '', raw_name) or f'node_{int(time.time())}'
    item = normalize_managed_outbound({
        'name': name,
        'address': payload.get('add'),
        'remote_port': payload.get('port'),
        'id': payload.get('id'),
        'aid': payload.get('aid') or 0,
        'security': payload.get('scy') or 'auto',
        'network': payload.get('net') or 'tcp',
        'header_type': payload.get('type') or 'none',
        'host': payload.get('host') or '',
        'path': payload.get('path') or '',
        'tls': payload.get('tls') or '',
        'sni': payload.get('sni') or '',
        'alpn': payload.get('alpn') or '',
        'fp': payload.get('fp') or '',
        'insecure': payload.get('allowInsecure') or payload.get('insecure') or '0',
        'probe_port': probe_port,
    })
    return item


def add_node(input_data):
    def mutation(outbounds, state, legacy, routes):
        outbound = parse_vmess_uri(input_data.get('uri'), next_probe_port(outbounds, state, legacy))
        name = outbound['name']
        if outbound_by_name(outbounds, name) is not None or route_by_code(routes, name) is not None:
            raise RuntimeError('节点标签已经存在')
        enable_ix = input_bool(input_data, 'enable_ix', True)
        outbounds.append(outbound)
        if enable_ix:
            add_legacy_ix_binding(legacy, name)
            routes['routes'].append(route_entry(name, outbound, legacy))
        add_dn42_member(state, name)
        if enable_ix:
            visibility = read_visibility()
            visibility[name] = True
            write_visibility(visibility)
        node_type = 'IX 线路' if enable_ix else 'IXR 专用出口'
        return {'success': True, 'message': f'{node_type}已添加并同步到 Xray', 'tag': name}

    return mutate_and_apply('导入统一出口', mutation)


def delete_node(input_data):
    route_code = validate_existing_name(input_data.get('tag'))
    target = {}

    def mutation(outbounds, state, legacy, routes):
        outbound = outbound_by_name(outbounds, route_code)
        route = route_by_code(routes, route_code)
        outbound_tag = str(
            (outbound or {}).get('tag')
            or (route or {}).get('outbound_tag')
            or ('via-' + safe_tag(route_code))
        )
        legacy_matches = [
            item for item in legacy.get('legacy_routes') or []
            if isinstance(item, dict) and str(item.get('route_code') or '') == route_code
        ]
        assignment_count = route_assignments(route_code, outbound_tag)
        if outbound is None and route is None and not legacy_matches and assignment_count == 0:
            raise RuntimeError('未找到对应的出口或 IX 线路')
        target['outbound_tag'] = outbound_tag
        target['is_ix_route'] = route is not None or bool(legacy_matches) or assignment_count > 0
        removed_emails = {
            str(item.get('email') or '')
            for item in legacy_matches
        }
        legacy['legacy_routes'] = [
            item for item in legacy.get('legacy_routes') or []
            if not (isinstance(item, dict) and str(item.get('route_code') or '') == route_code)
        ]
        still_used = {
            str(item.get('email') or '')
            for item in legacy.get('legacy_routes') or []
            if isinstance(item, dict)
        }
        shared = shared_inbound(legacy)
        shared['settings']['clients'] = [
            client for client in (shared.get('settings') or {}).get('clients') or []
            if not (isinstance(client, dict) and str(client.get('email') or '') in removed_emails - still_used)
        ]
        outbounds[:] = [item for item in outbounds if not (isinstance(item, dict) and str(item.get('name') or '') == route_code)]
        routes['routes'] = [item for item in routes.get('routes') or [] if not (isinstance(item, dict) and str(item.get('route_code') or '') == route_code)]
        update_state_references(state, route_code, None)
        if outbound_tag != route_code:
            update_state_references(state, outbound_tag, None)
        visibility = read_visibility()
        visibility.pop(route_code, None)
        write_visibility(visibility)
        return {'success': True, 'message': '出口已删除并同步到 Xray'}

    def database_mutation(result):
        count = deactivate_route_assignments(route_code, target['outbound_tag'])
        label = 'IX 线路' if target['is_ix_route'] else 'IXR 出口'
        result['message'] = f'{label}已删除，已自动解除 {count} 个用户授权并同步到 Xray'

    return mutate_and_apply(f'删除统一出口 {route_code}', mutation, database_mutation)


def edit_inbound_port(input_data):
    new_port = validate_port(input_data.get('new_port'), '监听端口')

    def mutation(outbounds, state, legacy, routes):
        shared = shared_inbound(legacy)
        current_port = int(shared.get('port') or legacy.get('shared_port') or DEFAULT_SHARED_PORT)
        reserved = {10085, 10185, 10198, 10199}
        reserved.update(int(item.get('port') or 0) for item in state.get('ports') or [] if isinstance(item, dict))
        reserved.update(int(item.get('probe_port') or item.get('port') or 0) for item in outbounds if isinstance(item, dict))
        reserved.update(
            int(item.get('port') or 0)
            for item in legacy.get('inbounds') or []
            if isinstance(item, dict) and item is not shared
        )
        reserved.discard(current_port)
        if new_port in reserved:
            raise RuntimeError('该端口已被 IXR/Xray 其他功能占用')
        shared['port'] = new_port
        legacy['shared_port'] = new_port
        for route in routes.get('routes') or []:
            if isinstance(route, dict):
                route['port'] = new_port
        return {'success': True, 'message': '主监听端口已更新并同步到 Xray'}

    return mutate_and_apply('IX Admin 修改共享监听端口', mutation)


def edit_front_host(input_data):
    host = normalize_front_host(input_data.get('front_entry_host'))
    with open_lock():
        snapshot = snapshot_files([IX_ROUTES, FRONT_HOST_FILE])
        try:
            routes = read_required_json(IX_ROUTES, 'IX 线路目录')
            if not isinstance(routes, dict):
                raise RuntimeError('IX 线路目录格式错误')
            for route in routes.get('routes') or []:
                if isinstance(route, dict):
                    route['address'] = host
            write_json(IX_ROUTES, routes, file_profile(IX_ROUTES, 0o640, 'root', 'www-data'))
            write_text(FRONT_HOST_FILE, host, file_profile(FRONT_HOST_FILE, 0o600, 'www-data', 'www-data'))
        except Exception:
            restore_files(snapshot)
            raise
    return {'success': True, 'message': '连接地址已更新', 'front_entry_host': host}


def test_node_ips():
    outbounds, _state, _legacy, routes = load_canonical()
    targets = []
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        name = str(outbound.get('name') or '')
        if name:
            targets.append((name, int(outbound.get('probe_port') or outbound.get('port') or 0)))

    def run_one(item):
        name, probe_port = item
        if probe_port <= 0:
            return name, '端口未分配'
        result = subprocess.run(
            [
                'curl', '--silent', '--show-error', '--max-time', '8',
                '--proxy', f'socks5h://127.0.0.1:{probe_port}', 'http://api.ipify.org',
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        value = (result.stdout or '').strip()
        try:
            socket.inet_aton(value)
            return name, value
        except OSError:
            return name, '获取超时或不通'

    with ThreadPoolExecutor(max_workers=min(10, max(1, len(targets)))) as executor:
        results = dict(executor.map(run_one, targets))
    write_json(NODE_IP_CACHE, results, file_profile(NODE_IP_CACHE, 0o600, 'www-data', 'www-data'))
    return {'success': True, 'message': 'Xray 真实出口 IP 探测完毕'}


class open_lock:
    def __enter__(self):
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        self.handle = os.fdopen(descriptor, 'r+')
        fcntl.flock(self.handle, fcntl.LOCK_EX)
        return self.handle

    def __exit__(self, exc_type, exc, traceback):
        fcntl.flock(self.handle, fcntl.LOCK_UN)
        self.handle.close()


def dispatch(action, input_data):
    if action == 'get_data':
        with open_lock():
            return panel_data()
    if action == 'edit_node':
        with open_lock():
            return edit_node(input_data)
    if action == 'create_node':
        with open_lock():
            return create_node(input_data)
    if action == 'update_binding':
        with open_lock():
            return update_binding(input_data)
    if action == 'add_node_from_uri':
        with open_lock():
            return add_node(input_data)
    if action == 'edit_client_uuid':
        with open_lock():
            return edit_client_uuid(input_data)
    if action == 'delete_node':
        with open_lock():
            return delete_node(input_data)
    if action == 'edit_inbound_port':
        with open_lock():
            return edit_inbound_port(input_data)
    if action == 'edit_front_entry_host':
        return edit_front_host(input_data)
    if action == 'restart_service':
        with open_lock():
            apply_xray('IX Admin 手动应用 Xray 配置')
        return {'success': True, 'message': 'Xray 配置已重新生成并应用'}
    if action == 'test_node_ips':
        with open_lock():
            return test_node_ips()
    if action == 'change_password':
        raise RuntimeError('IX Admin 使用 IXR 统一登录，请从部署配置修改密码')
    raise RuntimeError('不支持的 IX Admin 操作')


def main():
    request = json.loads(sys.stdin.read() or '{}')
    if not isinstance(request, dict):
        raise RuntimeError('请求格式错误')
    action = str(request.get('action') or '').strip()
    input_data = request.get('input') if isinstance(request.get('input'), dict) else {}
    result = dispatch(action, input_data)
    print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'success': False, 'error': str(exc)}, ensure_ascii=False, separators=(',', ':')))
        raise SystemExit(1)
