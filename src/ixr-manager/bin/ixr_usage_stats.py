#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
from pathlib import Path

DATA = Path('/opt/ixr-manager/data')
OUTS = DATA / 'outbounds.json'
STATE = DATA / 'state.json'
USAGE = DATA / 'usage.json'
BASELINE = DATA / 'usage_baseline.json'
XRAY = '/usr/local/bin/xray'
SERVER = '127.0.0.1:10085'


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

    try:
        raw_outbound_stats = parse_direction_stats(query_stats('outbound>>>'), 'outbound')
        raw_inbound_stats = parse_direction_stats(query_stats('inbound>>>'), 'inbound')
        baseline = read_json(BASELINE, {}) or {}
        baseline_reset_at = int(baseline.get('reset_at') or 0) if isinstance(baseline, dict) else 0
        baseline_outbound = baseline.get('outbound', {}) if isinstance(baseline, dict) else {}
        baseline_inbound = baseline.get('inbound', {}) if isinstance(baseline, dict) else {}
        xray_started_at = get_xray_started_at()
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
    except Exception as exc:
        payload = {
            'updated_at': int(time.time()),
            'available': False,
            'error': str(exc),
            'nodes': [],
            'ports': [],
            'outbounds_by_port': [],
            'total_bytes': 0,
            'port_total_bytes': 0,
            'stats_since_at': 0,
        }
        write_json(USAGE, payload)
        os.chmod(USAGE, 0o664)
        print('ERROR: xray stats unavailable')
        return 1

    managed_ports = []
    for port_config in port_configs:
        try:
            managed_ports.append(int(port_config.get('port')))
        except Exception:
            continue

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

    payload = {
        'updated_at': int(time.time()),
        'available': True,
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
    }
    write_json(USAGE, payload)
    os.chmod(USAGE, 0o664)
    print('OK: usage stats updated')
    print('OUTBOUND_TOTAL_BYTES:', total_bytes)
    print('PORT_TOTAL_BYTES:', port_total_bytes)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
