#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DATA = Path('/opt/ixr-manager/data')
OUTS = DATA / 'outbounds.json'
HEALTH = DATA / 'health.json'
APPLY = '/usr/local/bin/ixr-apply'
TARGETS = [
    'https://www.gstatic.com/generate_204',
    'https://www.youtube.com/generate_204',
    'https://youtubei.googleapis.com/generate_204',
    'https://play.googleapis.com/generate_204',
    'https://cp.cloudflare.com/generate_204',
]
DN42_TARGETS = [
    'http://map.dn42/',
    'https://map.dn42/',
]
FAIL_THRESHOLD = 3
RECOVER_THRESHOLD = 2
MAX_WORKERS = 8


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception:
        return default


def write_json(path, data):
    tmp = Path(str(path) + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(tmp, path)


def probe_one(port, url):
    cmd = [
        'curl', '-4', '--socks5-hostname', f'127.0.0.1:{port}',
        '-k', '-L', '-m', '6', '-o', '/dev/null', '-sS',
        '-w', '%{http_code} %{time_total}', url,
    ]
    started = time.time()
    try:
        result = subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=8,
        )
        parts = (result.stdout or '').strip().split()
        code = parts[0] if parts else '000'
        latency = float(parts[1]) if len(parts) > 1 else None
        ok = result.returncode == 0 and code in ('200', '204', '301', '302')
        error_lines = (result.stderr or '').strip().splitlines()
        return {
            'url': url,
            'ok': ok,
            'code': code,
            'latency': latency,
            'error': error_lines[-1:] if error_lines else [],
            'elapsed': round(time.time() - started, 3),
        }
    except Exception as exc:
        return {
            'url': url,
            'ok': False,
            'code': '000',
            'latency': None,
            'error': [str(exc)],
            'elapsed': round(time.time() - started, 3),
        }


def probe_tcp_connect(outbound):
    address = str(outbound.get('address') or '').strip()
    remote_port = int(outbound.get('remote_port') or 0)
    if not address or remote_port <= 0:
        return None, {
            'ok': False,
            'address': address,
            'port': remote_port,
            'error': 'missing address or remote_port',
            'attempts': [],
        }
    try:
        infos = socket.getaddrinfo(address, remote_port, socket.AF_INET, socket.SOCK_STREAM)
    except Exception as exc:
        return None, {
            'ok': False,
            'address': address,
            'port': remote_port,
            'error': str(exc),
            'attempts': [],
        }

    attempts = []
    for family, socktype, proto, _canonname, sockaddr in infos[:3]:
        started = time.time()
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(2.0)
        try:
            sock.connect(sockaddr)
            latency = time.time() - started
            attempts.append({
                'ok': True,
                'ip': sockaddr[0],
                'latency': latency,
                'latency_ms': round(latency * 1000),
            })
        except Exception as exc:
            attempts.append({
                'ok': False,
                'ip': sockaddr[0] if sockaddr else '',
                'latency': None,
                'latency_ms': None,
                'error': str(exc),
            })
        finally:
            sock.close()

    ok_attempts = [item for item in attempts if item.get('ok') and item.get('latency') is not None]
    if not ok_attempts:
        return None, {
            'ok': False,
            'address': address,
            'port': remote_port,
            'error': 'tcp connect failed',
            'attempts': attempts,
        }
    best = min(ok_attempts, key=lambda item: item['latency'])
    return best['latency'], {
        'ok': True,
        'address': address,
        'port': remote_port,
        'ip': best.get('ip'),
        'latency': best['latency'],
        'latency_ms': best['latency_ms'],
        'attempts': attempts,
    }


def probe_node(outbound):
    is_dn42 = 'DN42' in str(outbound.get('name', '')).upper()
    targets = DN42_TARGETS if is_dn42 else TARGETS
    # DN42 looking-glass targets are often slow/partial and may timeout even when
    # the VMess landing itself is reachable.  Treat DN42 as usable when either
    # one DN42 HTTP probe succeeds OR the remote VMess TCP endpoint is reachable.
    # This prevents false auto-isolation of usable DN42 exits such as TH-DN42/US-DN42.
    required_ok = 1 if is_dn42 else 4
    port = int(outbound.get('probe_port') or outbound.get('port') or 0)
    details = [probe_one(port, url) for url in targets]
    ok_details = [item for item in details if item['ok']]
    latency_values = [item['latency'] for item in ok_details if item['latency'] is not None]
    tcp_latency, tcp_detail = probe_tcp_connect(outbound)
    ok = len(ok_details) >= required_ok
    if is_dn42 and not ok and tcp_detail.get('ok'):
        ok = True
    latency = min(latency_values) if latency_values else tcp_latency
    return ok, latency, details, tcp_latency, tcp_detail


def merge_status(outbound, old, now):
    ok, latency, details, tcp_latency, tcp_detail = probe_node(outbound)
    fail_count = int(old.get('fail_count', 0))
    success_count = int(old.get('success_count', 0))
    old_status = old.get('status', 'unknown')
    status = old_status if old_status in ('healthy', 'warning', 'isolated') else 'healthy'

    if ok:
        success_count += 1
        fail_count = 0
        if status == 'isolated' and success_count >= RECOVER_THRESHOLD:
            status = 'healthy'
        elif status != 'isolated':
            status = 'healthy'
    else:
        fail_count += 1
        success_count = 0
        if fail_count >= FAIL_THRESHOLD:
            status = 'isolated'
        elif status != 'isolated':
            status = 'warning'

    if status != old_status:
        previous_status = old_status
        status_changed_at = now
    else:
        previous_status = old.get('previous_status', old_status)
        status_changed_at = old.get('status_changed_at') or old.get('last_check') or now

    offline_since = old.get('offline_since')
    if status == 'isolated':
        if old_status != 'isolated' or not offline_since:
            offline_since = status_changed_at or now
    else:
        offline_since = None

    last_online_at = old.get('last_online_at')
    if ok:
        last_online_at = now

    latency_ms = round(latency * 1000) if latency is not None else None
    tcp_latency_ms = round(tcp_latency * 1000) if tcp_latency is not None else None

    return outbound['name'], {
        'name': outbound['name'],
        'tag': outbound.get('tag'),
        'port': int(outbound.get('probe_port') or outbound.get('port') or 0),
        'status': status,
        'previous_status': previous_status,
        'status_changed_at': status_changed_at,
        'offline_since': offline_since,
        'last_online_at': last_online_at,
        'ok': ok,
        'latency': latency,
        'latency_ms': latency_ms,
        'tcp_latency': tcp_latency,
        'tcp_latency_ms': tcp_latency_ms,
        'tcp_detail': tcp_detail,
        'fail_count': fail_count,
        'success_count': success_count,
        'last_check': now,
        'details': details,
    }

def main():
    DATA.mkdir(parents=True, exist_ok=True)
    outbounds = read_json(OUTS, [])
    health = read_json(HEALTH, {})
    old_nodes = health.get('nodes', {}) if isinstance(health.get('nodes'), dict) else {}
    old_isolated = sorted(
        name for name, node in old_nodes.items()
        if node.get('status') == 'isolated'
    )
    now = int(time.time())
    new_nodes = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(merge_status, outbound, old_nodes.get(outbound['name'], {}), now)
            for outbound in outbounds
        ]
        for future in as_completed(futures):
            name, node = future.result()
            new_nodes[name] = node

    new_nodes = {name: new_nodes[name] for name in sorted(new_nodes)}
    new_isolated = sorted(
        name for name, node in new_nodes.items()
        if node.get('status') == 'isolated'
    )
    result = {
        'updated_at': now,
        'fail_threshold': FAIL_THRESHOLD,
        'recover_threshold': RECOVER_THRESHOLD,
        'targets': TARGETS,
        'dn42_targets': DN42_TARGETS,
        'nodes': new_nodes,
    }
    write_json(HEALTH, result)
    os.chmod(HEALTH, 0o664)

    print('ISOLATED:', ', '.join(new_isolated) if new_isolated else 'none')
    for name, node in new_nodes.items():
        print(
            f"{name}: {node['status']} fail={node['fail_count']} "
            f"recover={node['success_count']} latency={node['latency']} tcp={node.get('tcp_latency')}"
        )

    if old_isolated != new_isolated:
        print('POOL_CHANGED: applying xray config')
        applied = subprocess.run(
            [APPLY], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60,
        )
        print(applied.stdout)
        return applied.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
