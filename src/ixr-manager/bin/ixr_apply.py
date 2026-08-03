#!/usr/bin/env python3
import json
import os
import copy
import re
import subprocess
import sys
import uuid
import shutil
from pathlib import Path

BASE = Path('/opt/ixr-manager')
DATA = BASE / 'data'
STATE = DATA / 'state.json'
OUTS = DATA / 'outbounds.json'
HEALTH = DATA / 'health.json'
XRAY_CONFIG = Path('/usr/local/etc/xray/config.json')

SMART_GOOGLE_OUTBOUND = 'Google智能自动'
SMART_DN42_OUTBOUND = 'DN42智能自动'
GOOGLE_AUTO_NAMES = ('Example-US', 'Example-JP')
DN42_DNS_DEFAULT = ''


def configured_dn42_dns_servers():
    raw = os.environ.get('IXR_DN42_DNS_SERVERS', DN42_DNS_DEFAULT)
    servers = [item.strip() for item in raw.split(',') if item.strip()]
    return servers


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


def safe_tag(name):
    tag = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(name)).strip('-')
    return tag or 'node'


def port_out_tag(port, base_tag):
    return f'p{int(port)}-{base_tag}'


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
                'email': 'ixr-10186@example.com',
                'default': 'auto-fast',
                'rules': [
                    {'name': 'ChatGPT 强制 TH', 'domains': 'domain:chatgpt.com\ndomain:openai.com\ndomain:oaistatic.com\ndomain:oaiusercontent.com\ndomain:auth0.com\ndomain:statsigapi.net\ndomain:intercom.io', 'ips': '', 'outbound': 'Example-US'},
                    {'name': 'Gemini 强制 Example-JP', 'domains': 'domain:gemini.google.com\ndomain:aistudio.google.com\ndomain:generativelanguage.googleapis.com\ndomain:makersuite.google.com', 'ips': '', 'outbound': 'Example-JP'},
                ],
            },
            {'port': 10187, 'protocol': 'vmess', 'uuid': str(uuid.uuid4()), 'email': 'ixr-10187@example.com', 'default': 'auto-fast', 'rules': []},
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
            'email': str(item.get('email') or f'ixr-{port}@example.com'),
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


def build_config(state, outbounds):
    ports = state.get('ports', [])
    name_to_tag = {outbound['name']: outbound['tag'] for outbound in outbounds}
    smart_pools = normalize_smart_pools(state.get('smart_pools'))
    pool_by_name = {pool['name']: pool for pool in smart_pools}
    dn42_pool = pool_by_name.get(SMART_DN42_OUTBOUND)

    xouts = []
    for outbound in outbounds:
        xouts.append(xray_outbound(outbound, outbound['tag']))
        for port_config in ports:
            xouts.append(xray_outbound(outbound, port_out_tag(port_config['port'], outbound['tag'])))
    xouts += [
        {'tag': 'dns-out', 'protocol': 'dns'},
        {'tag': 'direct', 'protocol': 'freedom'},
        {'tag': 'block', 'protocol': 'blackhole'},
    ]

    inbounds = [{'tag': 'api', 'listen': '127.0.0.1', 'port': 10085, 'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'}}]
    rules = [{'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api', 'ruleTag': 'Xray 本机统计 API'}]
    balancers = []
    for outbound in outbounds:
        if outbound.get('kind') == 'vmess':
            probe_tag = 'probe-' + outbound['tag']
            inbounds.append({'tag': probe_tag, 'listen': '127.0.0.1', 'port': outbound['port'], 'protocol': 'socks', 'settings': {'udp': True}})
            rules.append({'type': 'field', 'inboundTag': [probe_tag], 'outboundTag': outbound['tag'], 'ruleTag': f"{outbound['name']} 健康检测入口"})

    jp_it7_tag = name_to_tag.get('Example-JP')
    if jp_it7_tag:
        rules.append({'type': 'field', 'ip': ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4'], 'port': '443', 'outboundTag': jp_it7_tag, 'ruleTag': 'DoH 上游 -> Example-JP'})
    dn42_dns_selector = smart_pool_tags(outbounds, dn42_pool) if dn42_pool else []
    dn42_dns_servers = configured_dn42_dns_servers()
    if dn42_dns_selector and dn42_dns_servers:
        dn42_dns_balancer_tag = 'dn42-auto-dns'
        rules.append({'type': 'field', 'ip': dn42_dns_servers, 'port': '53,5353', 'balancerTag': dn42_dns_balancer_tag, 'ruleTag': 'DN42 DNS 上游 -> DN42智能自动'})
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
                'clients': [{'id': port_config['uuid'], 'alterId': 0, 'email': port_config['email']}],
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
            domains = split_items(rule_config.get('domains', ''))
            ips = split_items(rule_config.get('ips', ''))
            if (base_tag or smart_pool) and (domains or ips):
                route_rule = {'type': 'field', 'inboundTag': [inbound_tag], 'ruleTag': rule_config.get('name') or '自定义规则'}
                if smart_pool:
                    pool_balancer_tag = ensure_smart_pool_balancer(smart_pool)
                    if not pool_balancer_tag:
                        continue
                    route_rule['balancerTag'] = pool_balancer_tag
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

    subject_selector = healthy_tags(outbounds)
    for port_config in ports:
        subject_selector.extend(healthy_port_tags(outbounds, port_config['port']))
    subject_selector = list(dict.fromkeys(subject_selector))

    dns_servers = []
    if dn42_dns_servers:
        dns_servers.append({'address': f"tcp://{dn42_dns_servers[0]}:53", 'domains': ['domain:dn42'], 'skipFallback': True})
    dns_servers += [
        {'address': 'https://1.1.1.1/dns-query', 'domains': ['geosite:geolocation-!cn']},
        {'address': 'https://8.8.8.8/dns-query'},
        'localhost',
    ]
    dns = {'queryStrategy': 'UseIPv4', 'servers': dns_servers}

    return {
        'log': {'access': '/var/log/xray/access.log', 'error': '/var/log/xray/error.log', 'loglevel': 'warning'},
        'stats': {},
        'api': {'tag': 'api', 'services': ['StatsService']},
        'policy': {'system': {'statsInboundUplink': True, 'statsInboundDownlink': True, 'statsOutboundUplink': True, 'statsOutboundDownlink': True}},
        'dns': dns,
        'observatory': {'subjectSelector': subject_selector, 'probeUrl': 'https://www.gstatic.com/generate_204', 'probeInterval': '30s', 'enableConcurrency': True},
        'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': rules, 'balancers': balancers},
        'inbounds': inbounds,
        'outbounds': xouts,
    }


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
    cfg = build_config(state, outbounds)
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    write_json(XRAY_CONFIG, cfg)
    test = subprocess.run(['/usr/local/bin/xray', 'run', '-test', '-config', str(XRAY_CONFIG)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if test.returncode != 0:
        print(test.stdout)
        return test.returncode
    subprocess.run(['systemctl', 'daemon-reload'], check=False)
    subprocess.run(['systemctl', 'enable', '--now', 'xray.service'], check=False)
    restart = subprocess.run(['systemctl', 'restart', 'xray.service'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if restart.returncode != 0:
        print(restart.stdout)
        return restart.returncode
    os.chmod(STATE, 0o664)
    os.chmod(OUTS, 0o664)
    try:
        shutil.chown(STATE, 'www-data', 'www-data')
        shutil.chown(OUTS, 'www-data', 'www-data')
    except Exception:
        pass
    print('OK: Xray 配置已生成并重启')
    print('PORTS:', ', '.join(str(port['port']) for port in state['ports']))
    print('AUTO_POOL:', ', '.join(healthy_tags(outbounds)))
    print('OUTBOUNDS:', ', '.join(outbound['name'] for outbound in outbounds))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
