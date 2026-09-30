#!/usr/bin/env python3
import json
import os
import copy
import re
import sqlite3
import subprocess
import sys
import uuid
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path('/opt/ixr-manager')
DATA = BASE / 'data'
STATE = DATA / 'state.json'
OUTS = DATA / 'outbounds.json'
HEALTH = DATA / 'health.json'
USERS_DB = DATA / 'users.db'
IX_LEGACY = DATA / 'ix_legacy.json'
XRAY_CONFIG = Path('/usr/local/etc/xray/config.json')
XRAY_BIN = '/usr/local/bin/xray'
XRAY_SERVICE = 'xray.service'
MANAGED_EMAIL_SUFFIX = '@ixr.local'

SMART_GOOGLE_OUTBOUND = 'Google智能自动'
SMART_DN42_OUTBOUND = 'DN42智能自动'
GOOGLE_AUTO_NAMES = ('JP-IT7', 'us-44net', 'TH2', 'US-GCP', 'SG-DN42', 'CA-NAT')


def default_smart_pools():
    return [
        {'id': 'google', 'name': SMART_GOOGLE_OUTBOUND, 'members': list(GOOGLE_AUTO_NAMES), 'keyword': ''},
        {'id': 'dn42', 'name': SMART_DN42_OUTBOUND, 'members': [], 'keyword': 'DN42'},
    ]


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return default


def write_json(path, data):
    tmp = Path(str(path) + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(tmp, path)


def active_ixr_port_assignments():
    if not USERS_DB.is_file():
        return []
    database = sqlite3.connect(f'file:{USERS_DB}?mode=ro', uri=True, timeout=10)
    database.row_factory = sqlite3.Row
    try:
        columns = {str(row[1]) for row in database.execute('PRAGMA table_info(user_ports)')}
        if not {'uuid', 'xray_email'}.issubset(columns):
            raise RuntimeError('IXR 共享端口数据库迁移尚未完成')
        has_routes = bool(database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_routes'").fetchone())
        route_total_sql = "COALESCE((SELECT SUM(history.traffic_used_bytes) FROM user_routes history WHERE history.user_id = u.id), 0)" if has_routes else '0'
        rows = database.execute(
            f'''
            SELECT up.id AS assignment_id, up.user_id, up.port, up.uuid, up.xray_email,
                   u.enabled, u.expires_at, u.traffic_limit_bytes,
                   COALESCE((SELECT SUM(history.traffic_used_bytes) FROM user_ports history WHERE history.user_id = u.id), 0)
                   + {route_total_sql} AS traffic_used_bytes
            FROM user_ports up
            JOIN users u ON u.id = up.user_id
            WHERE up.active = 1
            ORDER BY up.port, up.user_id, up.id
            '''
        ).fetchall()
    finally:
        database.close()

    now = datetime.now(timezone(timedelta(hours=8))).replace(tzinfo=None)
    assignments = []
    for row in rows:
        email = str(row['xray_email'] or '').strip()
        credential_uuid = str(row['uuid'] or '').strip()
        if not email.lower().endswith(MANAGED_EMAIL_SUFFIX) or not credential_uuid:
            raise RuntimeError(f"IXR 端口授权 #{int(row['assignment_id'])} 的凭证不完整")
        assignments.append({
            'assignment_id': int(row['assignment_id']),
            'user_id': int(row['user_id']),
            'port': int(row['port']),
            'uuid': credential_uuid,
            'email': email,
            'status': effective_user_status(row, int(row['traffic_used_bytes'] or 0), now),
        })
    return assignments


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


def active_ix_assignments():
    if not USERS_DB.is_file():
        return []
    database = sqlite3.connect(f'file:{USERS_DB}?mode=ro', uri=True, timeout=10)
    database.row_factory = sqlite3.Row
    try:
        has_routes = bool(database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_routes'").fetchone())
        if not has_routes:
            return []
        rows = database.execute(
            '''
            SELECT ur.id AS assignment_id, ur.user_id, ur.route_code, ur.outbound_tag,
                   ur.uuid, ur.xray_email, u.enabled, u.expires_at, u.traffic_limit_bytes,
                   COALESCE((SELECT SUM(up.traffic_used_bytes) FROM user_ports up WHERE up.user_id = u.id), 0)
                   + COALESCE((SELECT SUM(history.traffic_used_bytes) FROM user_routes history WHERE history.user_id = u.id), 0)
                   AS traffic_used_bytes
            FROM user_routes ur
            JOIN users u ON u.id = ur.user_id
            WHERE ur.active = 1
            ORDER BY ur.user_id, ur.route_code, ur.id
            '''
        ).fetchall()
    finally:
        database.close()

    now = datetime.now(timezone(timedelta(hours=8))).replace(tzinfo=None)
    assignments = []
    for row in rows:
        email = str(row['xray_email'] or '').strip()
        user_id = str(row['uuid'] or '').strip()
        route_code = str(row['outbound_tag'] or row['route_code'] or '').strip()
        if not email.lower().endswith(MANAGED_EMAIL_SUFFIX) or not user_id or not route_code:
            raise RuntimeError(f"IX 线路授权 #{int(row['assignment_id'])} 的凭证不完整")
        assignments.append({
            'assignment_id': int(row['assignment_id']),
            'route_code': route_code,
            'uuid': user_id,
            'email': email,
            'status': effective_user_status(row, int(row['traffic_used_bytes'] or 0), now),
        })
    return assignments


def normalize_ix_legacy(value):
    if not isinstance(value, dict) or int(value.get('version') or 0) != 1:
        return {'enabled': False, 'inbounds': [], 'legacy_routes': [], 'global_rules': [], 'policy_levels': {}}
    inbounds = [copy.deepcopy(item) for item in value.get('inbounds', []) if isinstance(item, dict)]
    legacy_routes = []
    for item in value.get('legacy_routes', []):
        if not isinstance(item, dict):
            continue
        email = str(item.get('email') or '').strip()
        route_code = str(item.get('route_code') or '').strip()
        if email and route_code and not email.lower().endswith(MANAGED_EMAIL_SUFFIX):
            legacy_routes.append({'email': email, 'route_code': route_code})
    global_rules = [copy.deepcopy(item) for item in value.get('global_rules', []) if isinstance(item, dict)]
    policy_levels = value.get('policy_levels') if isinstance(value.get('policy_levels'), dict) else {}
    return {
        'enabled': bool(value.get('enabled', True)),
        'shared_tag': str(value.get('shared_tag') or 'mixed').strip() or 'mixed',
        'shared_port': int(value.get('shared_port') or 10183),
        'inbounds': inbounds,
        'legacy_routes': legacy_routes,
        'global_rules': global_rules,
        'policy_levels': copy.deepcopy(policy_levels),
    }


def route_outbound_tag(route_code, name_to_tag):
    route_code = str(route_code or '').strip()
    tag = name_to_tag.get(route_code)
    if not tag and route_code.startswith('via-') and route_code in name_to_tag.values():
        tag = route_code
    if not tag:
        raise RuntimeError(f'IX 线路 {route_code or "<empty>"} 在 Xray 出口目录中不存在')
    return tag


def normalize_legacy_rule(rule, name_to_tag, migrated_tags=None):
    allowed = (
        'type', 'inboundTag', 'network', 'port', 'sourcePort', 'domain', 'ip',
        'source', 'protocol', 'user', 'attributes', 'domainMatcher', 'outboundTag',
        'balancerTag', 'ruleTag',
    )
    clean = {key: copy.deepcopy(rule[key]) for key in allowed if key in rule}
    clean['type'] = str(clean.get('type') or 'field')
    if 'ruleTag' not in clean and rule.get('marktag'):
        clean['ruleTag'] = str(rule.get('marktag'))
    if migrated_tags:
        allowed_tags = set(migrated_tags)
        inbound_tags = clean.get('inboundTag')
        if inbound_tags:
            if isinstance(inbound_tags, str):
                inbound_tags = [inbound_tags]
            scoped_tags = [tag for tag in inbound_tags if tag in allowed_tags]
            if not scoped_tags:
                return None
            clean['inboundTag'] = scoped_tags
        else:
            clean['inboundTag'] = list(migrated_tags)
    outbound_tag = str(clean.get('outboundTag') or '').strip()
    if outbound_tag and outbound_tag not in {'direct', 'block', 'dns-out'}:
        clean['outboundTag'] = route_outbound_tag(outbound_tag, name_to_tag)
    return clean


def append_unified_ix(inbounds, rules, name_to_tag, legacy, assignments):
    if not legacy.get('enabled'):
        return {'legacy_clients': 0, 'managed_clients': 0, 'blocked_clients': 0, 'inbounds': 0}

    existing_tags = {str(item.get('tag') or '') for item in inbounds if isinstance(item, dict)}
    existing_ports = {int(item.get('port') or 0) for item in inbounds if isinstance(item, dict)}
    shared_tag = legacy['shared_tag']
    shared_port = int(legacy['shared_port'])
    migrated_tags = []
    shared_found = False
    legacy_clients = 0
    seen_emails = set()
    seen_uuids = set()

    for source in legacy.get('inbounds', []):
        inbound = copy.deepcopy(source)
        tag = str(inbound.get('tag') or '').strip()
        port = int(inbound.get('port') or 0)
        if not tag or port <= 0:
            raise RuntimeError('迁移的 IX 入站缺少 tag 或 port')
        if tag in existing_tags or port in existing_ports:
            raise RuntimeError(f'迁移的 IX 入站与 Xray 现有配置冲突：{tag}/{port}')
        existing_tags.add(tag)
        existing_ports.add(port)
        migrated_tags.append(tag)

        if tag == shared_tag or port == shared_port:
            shared_found = True
            settings = inbound.setdefault('settings', {})
            clients = settings.get('clients') if isinstance(settings.get('clients'), list) else []
            retained = []
            for client in clients:
                if not isinstance(client, dict):
                    continue
                email = str(client.get('email') or '').strip()
                user_id = str(client.get('id') or '').strip()
                if email.lower().endswith(MANAGED_EMAIL_SUFFIX):
                    continue
                if not email or not user_id or email in seen_emails or user_id in seen_uuids:
                    raise RuntimeError('旧 IX 客户端存在空值或重复 UUID/email')
                seen_emails.add(email)
                seen_uuids.add(user_id)
                retained.append(client)
            legacy_clients = len(retained)
            for assignment in assignments:
                if assignment.get('status') != 'active':
                    continue
                email = assignment['email']
                user_id = assignment['uuid']
                if email in seen_emails or user_id in seen_uuids:
                    raise RuntimeError('IXR 托管客户端与旧 IX 客户端存在重复 UUID/email')
                seen_emails.add(email)
                seen_uuids.add(user_id)
                retained.append({'id': user_id, 'alterId': 0, 'email': email, 'level': 0})
            settings['clients'] = retained
        inbounds.append(inbound)

    if not shared_found:
        raise RuntimeError(f'迁移配置中未找到 IX 共享入站 {shared_tag}/{shared_port}')

    for route in legacy.get('legacy_routes', []):
        rules.append({
            'type': 'field',
            'inboundTag': [shared_tag],
            'user': [route['email']],
            'outboundTag': route_outbound_tag(route['route_code'], name_to_tag),
            'ruleTag': f"旧 IX 用户 -> {route['route_code']}",
        })
    for assignment in assignments:
        if assignment.get('status') != 'active':
            continue
        rules.append({
            'type': 'field',
            'inboundTag': [shared_tag],
            'user': [assignment['email']],
            'outboundTag': route_outbound_tag(assignment['route_code'], name_to_tag),
            'ruleTag': f"IXR 用户线路 #{assignment['assignment_id']} -> {assignment['route_code']}",
        })
    for rule in legacy.get('global_rules', []):
        normalized_rule = normalize_legacy_rule(rule, name_to_tag, migrated_tags)
        if normalized_rule:
            rules.append(normalized_rule)
    rules.append({
        'type': 'field',
        'inboundTag': migrated_tags,
        'outboundTag': 'direct',
        'ruleTag': '迁移 IX 入站默认直连',
    })
    return {
        'legacy_clients': legacy_clients,
        'managed_clients': sum(1 for item in assignments if item.get('status') == 'active'),
        'blocked_clients': sum(1 for item in assignments if item.get('status') != 'active'),
        'inbounds': len(migrated_tags),
    }


def managed_user_block_rules(ixr_port_assignments, ix_assignments, shared_tag):
    blocked = []
    for assignment in ixr_port_assignments:
        if assignment.get('status') == 'active':
            continue
        blocked.append({
            'type': 'field',
            'inboundTag': [f"in-{int(assignment['port'])}"],
            'user': [assignment['email']],
            'outboundTag': 'block',
            'ruleTag': f"ixr-user-block-ixr-{int(assignment['assignment_id'])}",
        })
    for assignment in ix_assignments:
        if assignment.get('status') == 'active':
            continue
        blocked.append({
            'type': 'field',
            'inboundTag': [shared_tag],
            'user': [assignment['email']],
            'outboundTag': 'block',
            'ruleTag': f"ixr-user-block-ix-{int(assignment['assignment_id'])}",
        })
    return blocked


def ixr_port_clients(port_config, assignments):
    managed_uuids = {str(item.get('uuid') or '') for item in assignments}
    managed_emails = {str(item.get('email') or '').lower() for item in assignments}
    clients = []
    seen_uuids = set()
    seen_emails = set()
    legacy_uuid = str(port_config.get('uuid') or '').strip()
    legacy_email = str(port_config.get('email') or '').strip()
    if legacy_uuid and legacy_email and legacy_uuid not in managed_uuids and legacy_email.lower() not in managed_emails:
        clients.append({'id': legacy_uuid, 'alterId': 0, 'email': legacy_email, 'level': 0})
        seen_uuids.add(legacy_uuid)
        seen_emails.add(legacy_email.lower())
    for assignment in assignments:
        if assignment.get('status') != 'active':
            continue
        credential_uuid = str(assignment.get('uuid') or '').strip()
        email = str(assignment.get('email') or '').strip()
        if not credential_uuid or not email or credential_uuid in seen_uuids or email.lower() in seen_emails:
            raise RuntimeError(f"IXR 端口 {int(port_config['port'])} 存在重复或空白客户端凭证")
        clients.append({'id': credential_uuid, 'alterId': 0, 'email': email, 'level': 0})
        seen_uuids.add(credential_uuid)
        seen_emails.add(email.lower())
    return clients


def safe_tag(name):
    tag = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(name)).strip('-')
    return tag or 'node'


def port_out_tag(port, base_tag):
    return f'p{int(port)}-{base_tag}'

def is_local_ip_outbound(name):
    text = str(name or '').strip()
    return text.startswith('localip:') and bool(text.split(':', 1)[1].strip())

def local_ip_from_outbound(name):
    return str(name or '').split(':', 1)[1].strip()

def local_ip_tag(ip):
    return 'localip-' + safe_tag(str(ip).replace(':', '-'))

def port_local_ip_tag(port, ip):
    return port_out_tag(port, local_ip_tag(ip))

def xray_local_ip_outbound(ip, tag):
    return {'tag': tag, 'protocol': 'freedom', 'sendThrough': ip, 'settings': {'domainStrategy': 'UseIPv4'}}


def normalize_managed_outbound(item):
    if not isinstance(item, dict):
        return None
    name = str(item.get('name') or '').strip()
    protocol = str(item.get('protocol') or 'vmess').strip().lower()
    if not name or protocol != 'vmess':
        return None
    try:
        remote_port = int(item.get('remote_port') or item.get('server_port') or 0)
        probe_port = int(item.get('probe_port') or item.get('local_port') or item.get('port') or 0)
    except Exception:
        return None
    address = str(item.get('address') or '').strip()
    user_id = str(item.get('id') or item.get('uuid') or '').strip()
    if not address or not remote_port or not probe_port or not user_id:
        return None
    clean = {
        'name': name,
        'protocol': 'vmess',
        'address': address,
        'remote_port': remote_port,
        'id': user_id,
        'aid': int(item.get('alterId') or item.get('aid') or 0),
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
    return clean


def xray_config_from_managed(item, tag):
    name = item['name']
    remote_port = item['remote_port']
    probe_port = item['probe_port']
    address = item['address']
    user_id = item['id']
    security = item['security']
    network = item['network']
    header_type = item['header_type']
    host = item['host']
    path = item['path']
    tls = item['tls']
    sni = item['sni']
    alpn = [part for part in re.split(r'[\n,\s]+', str(item.get('alpn') or '')) if part]
    fingerprint = item['fp']
    insecure = str(item.get('insecure') or '').strip().lower() in ('1', 'true', 'yes')
    stream = {'network': network}
    if network == 'ws':
        ws_settings = {}
        if path:
            ws_settings['path'] = path
        if host:
            ws_settings['headers'] = {'Host': host}
        stream['wsSettings'] = ws_settings
    elif network == 'grpc':
        stream['grpcSettings'] = {'serviceName': path.lstrip('/') or host}
    elif network == 'http':
        stream['httpSettings'] = {'path': path or '/', 'host': [host] if host else []}
    else:
        stream['tcpSettings'] = {'header': {'type': header_type}}
        if header_type == 'http' and host:
            stream['tcpSettings']['header']['request'] = {'headers': {'Host': [host]}}
    if tls:
        stream['security'] = tls
        if tls in ('tls', 'reality'):
            tls_settings = {}
            if sni or host:
                tls_settings['serverName'] = sni or host
            if alpn:
                tls_settings['alpn'] = alpn
            if fingerprint:
                tls_settings['fingerprint'] = fingerprint
            if insecure:
                tls_settings['allowInsecure'] = True
            stream['tlsSettings' if tls == 'tls' else 'realitySettings'] = tls_settings
    return {
        'name': name,
        'tag': tag,
        'port': probe_port,
        'kind': 'vmess',
        'xray': {
            'tag': tag,
            'protocol': 'vmess',
            'settings': {
                'vnext': [{
                    'address': address,
                    'port': remote_port,
                    'users': [{
                        'id': user_id,
                        'alterId': item['aid'],
                        'security': security,
                    }],
                }],
            },
            'streamSettings': stream,
        },
        'managed': item,
    }


def discover_managed_outbounds():
    raw = read_json(OUTS, []) or []
    found = []
    seen = set()
    if not isinstance(raw, list):
        return found
    for item in raw:
        clean = normalize_managed_outbound(item)
        if not clean or clean['name'] in seen:
            continue
        found.append(xray_config_from_managed(clean, clean['tag']))
        seen.add(clean['name'])
    return sorted(found, key=lambda item: (item['name'].lower(), item['port']))


def discover_outbounds():
    return discover_managed_outbounds()


def managed_outbounds(outbounds):
    return [outbound['managed'] for outbound in outbounds if outbound.get('managed')]


def xray_outbound(outbound, tag):
    if outbound.get('kind') == 'vmess':
        config = copy.deepcopy(outbound['xray'])
        config['tag'] = tag
        return config
    server = {'address': '127.0.0.1', 'port': outbound['port']}
    return {'tag': tag, 'protocol': 'socks', 'settings': {'servers': [server]}}


def default_state():
    return {
        'ports': [
            {
                'port': 10186,
                'protocol': 'vmess',
                'uuid': str(uuid.uuid4()),
                'email': 'ixr-10186@v2ray.com',
                'default': 'auto-fast',
                'rules': [
                    {'name': 'ChatGPT 强制 TH', 'domains': 'domain:chatgpt.com\ndomain:openai.com\ndomain:oaistatic.com\ndomain:oaiusercontent.com\ndomain:auth0.com\ndomain:statsigapi.net\ndomain:intercom.io', 'ips': '', 'outbound': 'TH-DN42'},
                    {'name': 'Gemini 强制 TH2', 'domains': 'domain:gemini.google.com\ndomain:aistudio.google.com\ndomain:generativelanguage.googleapis.com\ndomain:makersuite.google.com', 'ips': '', 'outbound': 'TH2'},
                ],
            },
            {'port': 10187, 'protocol': 'vmess', 'uuid': str(uuid.uuid4()), 'email': 'ixr-10187@v2ray.com', 'default': 'auto-fast', 'rules': []},
        ]
    }


def normalize_state(state):
    if not isinstance(state, dict):
        state = {}
    ports = state.get('ports') if isinstance(state.get('ports'), list) else []
    clean = []
    seen = set()
    for item in ports:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get('port'))
        except Exception:
            continue
        if port < 1 or port > 65535 or port in seen:
            continue
        seen.add(port)
        rules = item.get('rules') if isinstance(item.get('rules'), list) else []
        norm_rules = []
        for rule in rules:
            if isinstance(rule, dict):
                norm_rules.append({
                    'name': str(rule.get('name') or '自定义规则'),
                    'id': str(rule.get('id') or uuid.uuid4()),
                    'domains': str(rule.get('domains') or ''),
                    'ips': str(rule.get('ips') or ''),
                    'outbound': str(rule.get('outbound') or ''),
                })
        clean.append({
            'port': port,
            'protocol': 'vmess',
            'uuid': str(item.get('uuid') or uuid.uuid4()),
            'email': str(item.get('email') or f'ixr-{port}@v2ray.com'),
            'default': item.get('default') or 'auto-fast',
            'sniffRouteOnly': bool(item.get('sniffRouteOnly', True)),
            'rules': norm_rules,
        })
    return {'ports': sorted(clean, key=lambda item: item['port']), 'smart_pools': normalize_smart_pools(state.get('smart_pools'))}


def normalize_smart_pools(pools):
    raw = pools if isinstance(pools, list) else []
    result = []
    used_ids = set()
    used_names = set()

    def clean_pool(pool, default=None, builtin=False):
        source = pool if isinstance(pool, dict) else {}
        default = default or {}
        pool_id = str(default.get('id') if builtin else (source.get('id') or default.get('id') or safe_tag(source.get('name') or 'pool'))).strip()
        pool_id = re.sub(r'[^A-Za-z0-9_.-]+', '-', pool_id).strip('-') or 'pool'
        name = str(default.get('name') if builtin else (source.get('name') or default.get('name') or pool_id)).strip()
        members = source.get('members', default.get('members', []))
        if isinstance(members, str):
            members = split_items(members)
        if not isinstance(members, list):
            members = []
        members = list(dict.fromkeys(str(member).strip() for member in members if str(member).strip()))
        keyword = str(source.get('keyword', default.get('keyword', ''))).strip()
        return {'id': pool_id, 'name': name, 'members': members, 'keyword': keyword, 'builtin': bool(builtin)}

    for default in default_smart_pools():
        match = None
        for pool in raw:
            if isinstance(pool, dict) and (pool.get('id') == default['id'] or pool.get('name') == default['name']):
                match = pool
                break
        cleaned = clean_pool(match, default, True)
        result.append(cleaned)
        used_ids.add(cleaned['id'])
        used_names.add(cleaned['name'])

    for pool in raw:
        if not isinstance(pool, dict):
            continue
        if pool.get('id') in used_ids or pool.get('name') in used_names:
            continue
        cleaned = clean_pool(pool)
        if cleaned['id'] in used_ids or cleaned['name'] in used_names:
            continue
        result.append(cleaned)
        used_ids.add(cleaned['id'])
        used_names.add(cleaned['name'])
    return result


def split_items(text):
    raw = re.split(r'[\n,，\s]+', text or '')
    return [item.strip() for item in raw if item.strip()]


def healthy_names(outbounds):
    health = read_json(HEALTH, {}) or {}
    nodes = health.get('nodes', {}) if isinstance(health.get('nodes'), dict) else {}
    names = []
    for outbound in outbounds:
        node = nodes.get(outbound['name'], {})
        if node.get('status') != 'isolated':
            names.append(outbound['name'])
    if not names:
        names = [outbound['name'] for outbound in outbounds]
    return names


def healthy_tags(outbounds):
    names = set(healthy_names(outbounds))
    return [outbound['tag'] for outbound in outbounds if outbound['name'] in names]


def healthy_port_tags(outbounds, port):
    names = set(healthy_names(outbounds))
    return [port_out_tag(port, outbound['tag']) for outbound in outbounds if outbound['name'] in names]


def smart_pool_outbounds(outbounds, pool):
    members = set(str(member).strip() for member in pool.get('members', []) if str(member).strip())
    keyword = str(pool.get('keyword', '')).strip().upper()
    candidates = []
    for outbound in outbounds:
        name = str(outbound.get('name', ''))
        if name in members or (keyword and keyword in name.upper()):
            candidates.append(outbound)
    return candidates


def smart_pool_tags(outbounds, pool, port=None):
    health = read_json(HEALTH, {}) or {}
    nodes = health.get('nodes', {}) if isinstance(health.get('nodes'), dict) else {}
    candidates = smart_pool_outbounds(outbounds, pool)
    is_dn42_pool = pool.get('name') == SMART_DN42_OUTBOUND or str(pool.get('keyword', '')).strip().upper() == 'DN42'
    if is_dn42_pool:
        preferred = [outbound for outbound in candidates if nodes.get(outbound['name'], {}).get('status') == 'healthy']
    else:
        healthy = set(healthy_names(outbounds))
        preferred = [outbound for outbound in candidates if outbound['name'] in healthy]
    if not preferred and is_dn42_pool:
        preferred = [outbound for outbound in candidates if nodes.get(outbound['name'], {}).get('status') != 'isolated']
    if not preferred:
        preferred = candidates
    if port is None:
        return [outbound['tag'] for outbound in preferred]
    return [port_out_tag(port, outbound['tag']) for outbound in preferred]


def smart_pool_balancer_tag(pool, port):
    if pool.get('name') == SMART_GOOGLE_OUTBOUND:
        return f'google-auto-{port}'
    if pool.get('name') == SMART_DN42_OUTBOUND:
        return f'dn42-auto-{port}'
    return f'pool-{safe_tag(pool.get("id") or pool.get("name"))}-{port}'


def build_config(state, outbounds, ixr_port_assignments=None, ix_legacy=None, ix_assignments=None, summary=None):
    ixr_port_assignments = ixr_port_assignments if isinstance(ixr_port_assignments, list) else []
    ix_legacy = normalize_ix_legacy(ix_legacy)
    ix_assignments = ix_assignments if isinstance(ix_assignments, list) else []
    ports = list(state.get('ports', []))
    port_assignments = {}
    for assignment in ixr_port_assignments:
        port_assignments.setdefault(int(assignment['port']), []).append(assignment)
    name_to_tag = {outbound['name']: outbound['tag'] for outbound in outbounds}
    smart_pools = normalize_smart_pools(state.get('smart_pools'))
    pool_by_name = {pool['name']: pool for pool in smart_pools}
    dn42_pool = pool_by_name.get(SMART_DN42_OUTBOUND)

    xouts = []
    for outbound in outbounds:
        xouts.append(xray_outbound(outbound, outbound['tag']))
        for port_config in ports:
            xouts.append(xray_outbound(outbound, port_out_tag(port_config['port'], outbound['tag'])))
    local_ip_port_tags = set()
    for port_config in ports:
        port = port_config['port']
        for rule_config in port_config.get('rules', []):
            outbound_name = str(rule_config.get('outbound') or '')
            if is_local_ip_outbound(outbound_name):
                ip = local_ip_from_outbound(outbound_name)
                tag = port_local_ip_tag(port, ip)
                if tag not in local_ip_port_tags:
                    xouts.append(xray_local_ip_outbound(ip, tag))
                    local_ip_port_tags.add(tag)
    inbounds = [{'tag': 'api', 'listen': '127.0.0.1', 'port': 10085, 'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'}}]
    rules = [{'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api', 'ruleTag': 'Xray 本机统计 API'}]
    rules.extend(managed_user_block_rules(ixr_port_assignments, ix_assignments, ix_legacy.get('shared_tag') or 'mixed'))
    balancers = []
    for outbound in outbounds:
        if outbound.get('kind') == 'vmess':
            probe_tag = 'probe-' + outbound['tag']
            inbounds.append({'tag': probe_tag, 'listen': '127.0.0.1', 'port': outbound['port'], 'protocol': 'socks', 'settings': {'udp': True}})
            rules.append({'type': 'field', 'inboundTag': [probe_tag], 'outboundTag': outbound['tag'], 'ruleTag': f"{outbound['name']} 健康检测入口"})

    ix_summary = append_unified_ix(inbounds, rules, name_to_tag, ix_legacy, ix_assignments)

    jp_it7_tag = name_to_tag.get('JP-IT7')
    if jp_it7_tag:
        rules.append({'type': 'field', 'ip': ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4'], 'port': '443', 'outboundTag': jp_it7_tag, 'ruleTag': 'DoH 上游 -> JP-IT7'})
    dn42_dns_selector = smart_pool_tags(outbounds, dn42_pool) if dn42_pool else []
    if dn42_dns_selector:
        dn42_dns_balancer_tag = 'dn42-auto-dns'
        rules.append({'type': 'field', 'ip': ['172.20.0.53', '172.22.107.1', '172.22.107.5', '172.22.107.8'], 'port': '53,5353', 'balancerTag': dn42_dns_balancer_tag, 'ruleTag': 'DN42 DNS 上游 -> DN42智能自动'})
        balancers.append({'tag': dn42_dns_balancer_tag, 'selector': dn42_dns_selector, 'fallbackTag': 'direct', 'strategy': {'type': 'leastPing'}})

    for port_config in ports:
        port = port_config['port']
        inbound_tag = f'in-{port}'
        port_balancers = set()

        def ensure_smart_pool_balancer(pool):
            tag = smart_pool_balancer_tag(pool, port)
            if tag in port_balancers:
                return tag
            selector = smart_pool_tags(outbounds, pool, port)
            if not selector:
                return ''
            balancers.append({'tag': tag, 'selector': selector, 'fallbackTag': 'direct', 'strategy': {'type': 'leastPing'}})
            port_balancers.add(tag)
            return tag

        inbounds.append({
            'tag': inbound_tag,
            'listen': '0.0.0.0',
            'port': port,
            'protocol': 'vmess',
            'settings': {
                'clients': ixr_port_clients(port_config, port_assignments.get(int(port), [])),
                'disableInsecureEncryption': False,
            },
            'streamSettings': {'network': 'tcp', 'tcpSettings': {'header': {'type': 'none'}}},
            'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': bool(port_config.get('sniffRouteOnly', True))},
        })
        rules.append({'type': 'field', 'inboundTag': [inbound_tag], 'network': 'tcp,udp', 'port': '53', 'outboundTag': 'dns-out', 'ruleTag': f'{port} DNS 接管'})
        dn42_balancer_tag = ensure_smart_pool_balancer(dn42_pool) if dn42_pool else ''
        if dn42_balancer_tag:
            rules.append({'type': 'field', 'inboundTag': [inbound_tag], 'domain': ['domain:dn42'], 'balancerTag': dn42_balancer_tag, 'ruleTag': f'{port} .dn42 域名连接 -> DN42智能自动'})
        for rule_config in port_config.get('rules', []):
            outbound_name = str(rule_config.get('outbound') or '')
            smart_pool = pool_by_name.get(outbound_name)
            base_tag = name_to_tag.get(outbound_name)
            local_ip = local_ip_from_outbound(outbound_name) if is_local_ip_outbound(outbound_name) else ''
            domains = split_items(rule_config.get('domains', ''))
            ips = split_items(rule_config.get('ips', ''))
            # UI uses '*' to mean match all. Xray does not accept '*' as an IP/domain
            # address, so omit domain/ip fields and keep only inboundTag + outbound.
            wildcard_all = ('*' in domains) or ('*' in ips)
            domains = [item for item in domains if item != '*']
            ips = [item for item in ips if item != '*']
            # Empty domain/IP fields in a port route rule mean match-all for that inbound.
            # This is how the Web UI stores an "all" rule after removing the invalid '*'.
            match_all = wildcard_all or (not domains and not ips)
            if (base_tag or smart_pool or local_ip) and (match_all or domains or ips):
                route_rule = {'type': 'field', 'inboundTag': [inbound_tag], 'ruleTag': rule_config.get('name') or '?????'}
                if smart_pool:
                    pool_balancer_tag = ensure_smart_pool_balancer(smart_pool)
                    if not pool_balancer_tag:
                        continue
                    route_rule['balancerTag'] = pool_balancer_tag
                elif local_ip:
                    route_rule['outboundTag'] = port_local_ip_tag(port, local_ip)
                else:
                    route_rule['outboundTag'] = port_out_tag(port, base_tag)
                if domains:
                    route_rule['domain'] = domains
                if ips:
                    route_rule['ip'] = ips
                rules.append(route_rule)
        balancer_tag = f'auto-fast-{port}'
        rules.append({'type': 'field', 'inboundTag': [inbound_tag], 'network': 'tcp,udp', 'balancerTag': balancer_tag, 'ruleTag': f'{port} 默认自动低延迟'})
        balancers.append({'tag': balancer_tag, 'selector': healthy_port_tags(outbounds, port), 'fallbackTag': 'direct', 'strategy': {'type': 'leastPing'}})

    subject_selector = ['via-']
    subject_selector.extend(f"p{int(port_config['port'])}-via-" for port_config in ports)

    dns = {
        'queryStrategy': 'UseIPv4',
        'servers': [
            {'address': 'tcp://172.20.0.53:53', 'domains': ['domain:dn42'], 'skipFallback': True},
            {'address': 'https://1.1.1.1/dns-query', 'domains': ['geosite:geolocation-!cn']},
            {'address': 'https://8.8.8.8/dns-query'},
            'localhost',
        ],
    }

    policy_levels = copy.deepcopy(ix_legacy.get('policy_levels') or {})
    level_zero = policy_levels.setdefault('0', {})
    level_zero['statsUserUplink'] = True
    level_zero['statsUserDownlink'] = True

    config = {
        'log': {'access': '/var/log/xray/access.log', 'error': '/var/log/xray/error.log', 'loglevel': 'warning'},
        'stats': {},
        'api': {'tag': 'api', 'services': ['HandlerService', 'RoutingService', 'StatsService']},
        'policy': {
            'levels': policy_levels,
            'system': {'statsInboundUplink': True, 'statsInboundDownlink': True, 'statsOutboundUplink': True, 'statsOutboundDownlink': True},
        },
        'dns': dns,
        'observatory': {'subjectSelector': subject_selector, 'probeUrl': 'https://www.gstatic.com/generate_204', 'probeInterval': '30s', 'enableConcurrency': True},
        'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': rules, 'balancers': balancers},
        'inbounds': inbounds,
        'outbounds': xouts,
    }
    if isinstance(summary, dict):
        summary.update(ix_summary)
        summary['ixr_managed_clients'] = sum(1 for item in ixr_port_assignments if item.get('status') == 'active')
        summary['ixr_blocked_clients'] = sum(1 for item in ixr_port_assignments if item.get('status') != 'active')
    return config


def restore_xray_config(rollback_config, had_current_config, service_was_active):
    try:
        if had_current_config:
            if not rollback_config.is_file():
                raise RuntimeError('旧 Xray 配置备份不存在')
            os.replace(rollback_config, XRAY_CONFIG)
        else:
            XRAY_CONFIG.unlink(missing_ok=True)
    except Exception as exc:
        print(f'CRITICAL: Xray 配置自动恢复失败：{exc}', file=sys.stderr)
        return False

    action = 'restart' if service_was_active or had_current_config else 'stop'
    restored = subprocess.run(
        ['systemctl', action, XRAY_SERVICE],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if restored.returncode != 0:
        print(f'CRITICAL: Xray 服务自动恢复失败：\n{restored.stdout}', file=sys.stderr)
        return False
    print('ROLLBACK: 已自动恢复切换前的 Xray 配置和服务状态', file=sys.stderr)
    return True


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    state = normalize_state(read_json(STATE, None) or default_state())
    if not state['ports']:
        state = normalize_state(default_state())
    outbounds = discover_outbounds()
    if not outbounds:
        print('ERROR: 未配置 IXR 自管出口，请先在出口管理中导入或保存至少一个 VMess 出口', file=sys.stderr)
        return 2
    write_json(STATE, state)
    write_json(OUTS, managed_outbounds(outbounds))
    ixr_port_assignments = active_ixr_port_assignments()
    ix_legacy = read_json(IX_LEGACY, {}) or {}
    ix_assignments = active_ix_assignments()
    ix_summary = {}
    cfg = build_config(state, outbounds, ixr_port_assignments, ix_legacy, ix_assignments, ix_summary)
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    staged_config = Path(str(XRAY_CONFIG) + '.ixr-stage.json')
    rollback_config = Path(str(XRAY_CONFIG) + '.ixr-rollback')
    write_json(staged_config, cfg)
    test = subprocess.run([XRAY_BIN, 'run', '-test', '-config', str(staged_config)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if test.returncode != 0:
        print(test.stdout)
        staged_config.unlink(missing_ok=True)
        return test.returncode
    had_current_config = XRAY_CONFIG.is_file()
    current_config = read_json(XRAY_CONFIG, None)
    changed = current_config != cfg
    if changed:
        rollback_config.unlink(missing_ok=True)
        if had_current_config:
            shutil.copy2(XRAY_CONFIG, rollback_config)
        os.replace(staged_config, XRAY_CONFIG)
    else:
        staged_config.unlink(missing_ok=True)

    service_was_active = subprocess.run(
        ['systemctl', 'is-active', '--quiet', XRAY_SERVICE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    subprocess.run(['systemctl', 'daemon-reload'], check=False)
    enabled = subprocess.run(
        ['systemctl', 'enable', XRAY_SERVICE],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if enabled.returncode != 0:
        print(enabled.stdout)
        if changed:
            restore_xray_config(rollback_config, had_current_config, service_was_active)
        return enabled.returncode

    action = 'restart' if changed else 'start'
    started = subprocess.run(
        ['systemctl', action, XRAY_SERVICE],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    active = subprocess.run(
        ['systemctl', 'is-active', '--quiet', XRAY_SERVICE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    if started.returncode != 0 or not active:
        print(started.stdout)
        if changed:
            restore_xray_config(rollback_config, had_current_config, service_was_active)
        return started.returncode or 1
    rollback_config.unlink(missing_ok=True)
    os.chmod(STATE, 0o664)
    os.chmod(OUTS, 0o664)
    try:
        shutil.chown(STATE, 'www-data', 'www-data')
        shutil.chown(OUTS, 'www-data', 'www-data')
    except Exception:
        pass
    print('OK: Xray 配置已生成并重启' if changed else 'OK: Xray 配置无需变更')
    print('PORTS:', ', '.join(str(port['port']) for port in state['ports']))
    print('AUTO_POOL:', ', '.join(healthy_tags(outbounds)))
    print('OUTBOUNDS:', ', '.join(outbound['name'] for outbound in outbounds))
    if ix_summary:
        print('UNIFIED_IX_INBOUNDS:', int(ix_summary.get('inbounds') or 0))
        print('UNIFIED_IX_LEGACY_CLIENTS:', int(ix_summary.get('legacy_clients') or 0))
        print('UNIFIED_IX_MANAGED_CLIENTS:', int(ix_summary.get('managed_clients') or 0))
        print('UNIFIED_IX_BLOCKED_CLIENTS:', int(ix_summary.get('blocked_clients') or 0))
        print('IXR_MANAGED_CLIENTS:', int(ix_summary.get('ixr_managed_clients') or 0))
        print('IXR_BLOCKED_CLIENTS:', int(ix_summary.get('ixr_blocked_clients') or 0))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
