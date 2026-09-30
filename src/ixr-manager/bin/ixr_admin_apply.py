#!/usr/bin/env python3
import copy
import fcntl
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import ixr_apply


XRAY = ixr_apply.XRAY_BIN
XRAY_CONFIG = ixr_apply.XRAY_CONFIG
XRAY_SERVICE = ixr_apply.XRAY_SERVICE
SERVER = '127.0.0.1:10085'
FULL_APPLY = '/usr/local/bin/ixr-apply'
APPLY_LOCK = Path('/run/lock/ixr-admin-apply.lock')
RUNTIME_LOCK = Path('/run/lock/ixr-runtime-sync.lock')
STATUS = ixr_apply.DATA / 'admin_apply_status.json'
DYNAMIC_USER_VERIFY_ATTEMPTS = 20
DYNAMIC_USER_VERIFY_DELAY = 0.05


class DynamicUnsupported(RuntimeError):
    pass


def ensure_dynamic_routing_supported(source, target):
    source_routing = source.get('routing') or {}
    target_routing = target.get('routing') or {}
    if source_routing == target_routing:
        return
    raise DynamicUnsupported('Xray 路由规则发生变化，改用完整应用以避开动态 API 消息上限')


@contextmanager
def file_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    handle = os.fdopen(descriptor, 'r+')
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield handle
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def write_status(status, reason, mode, started_at, error=''):
    payload = {
        'status': status,
        'mode': mode,
        'reason': str(reason)[:400],
        'started_at': int(started_at),
        'finished_at': int(time.time()),
        'error': str(error)[:1600],
    }
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATUS.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.replace(temporary, STATUS)
    os.chmod(STATUS, 0o664)
    try:
        shutil.chown(STATUS, 'www-data', 'www-data')
    except Exception:
        pass


def run(command, timeout=60, check=True):
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        output = (result.stdout or '').replace('\n', ' | ')[-1600:]
        raise RuntimeError(f"命令执行失败（{result.returncode}）：{output}")
    return result


def run_api(arguments, timeout=30):
    return run([XRAY, 'api', *arguments], timeout=timeout).stdout or ''


def parse_json_output(output):
    start = output.find('{')
    if start < 0:
        return {}
    return json.loads(output[start:])


def temporary_json(payload):
    descriptor, name = tempfile.mkstemp(prefix='ixr-admin-runtime-', suffix='.json')
    path = Path(name)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    return path


def runtime_tags(command, key):
    payload = parse_json_output(run_api([command, f'--server={SERVER}']))
    return {
        str(item.get('tag') or '')
        for item in payload.get(key) or []
        if isinstance(item, dict) and item.get('tag')
    }


def runtime_emails(tag):
    payload = parse_json_output(run_api(['inbounduser', f'--server={SERVER}', f'-tag={tag}']))
    return {
        str(item.get('email') or '').strip().lower()
        for item in payload.get('users') or []
        if isinstance(item, dict) and str(item.get('email') or '').strip()
    }


def wait_runtime_email_state(tag, expected_present, expected_absent):
    expected_present = set(expected_present)
    expected_absent = set(expected_absent)
    current = set()
    for attempt in range(DYNAMIC_USER_VERIFY_ATTEMPTS):
        current = runtime_emails(tag)
        if expected_present.issubset(current) and not (expected_absent & current):
            return current
        if attempt + 1 < DYNAMIC_USER_VERIFY_ATTEMPTS:
            time.sleep(DYNAMIC_USER_VERIFY_DELAY)
    missing = len(expected_present - current)
    unexpected = len(expected_absent & current)
    raise RuntimeError(f'Xray 入站 {tag} 的动态用户状态未收敛（缺少 {missing}，残留 {unexpected}）')


def add_handlers(field, command, entries):
    if not entries:
        return
    path = temporary_json({field: entries})
    try:
        run_api([command, f'--server={SERVER}', str(path)])
    finally:
        path.unlink(missing_ok=True)


def remove_handlers(command, tags):
    if tags:
        run_api([command, f'--server={SERVER}', *sorted(tags)])


def replace_routing(routing):
    path = temporary_json({'routing': routing})
    try:
        run_api(['adrules', f'--server={SERVER}', str(path)])
    finally:
        path.unlink(missing_ok=True)


def remove_users(tag, emails):
    if emails:
        run_api(['rmu', f'--server={SERVER}', f'-tag={tag}', *emails])


def add_users(inbound, clients):
    if not clients:
        return
    value = copy.deepcopy(inbound)
    tag = str(value.get('tag') or '')
    settings = value.get('settings')
    if not tag or not isinstance(settings, dict):
        raise RuntimeError('Xray 动态用户配置缺少完整入站信息')
    settings['clients'] = [copy.deepcopy(client) for client in clients]
    path = temporary_json({'inbounds': [value]})
    try:
        output = run_api(['adu', f'--server={SERVER}', str(path)])
        lowered = output.lower()
        if 'failed to build config:' in lowered or 'added 0 user(s)' in lowered:
            raise RuntimeError(f'Xray 入站 {tag} 未接受动态用户配置')
    finally:
        path.unlink(missing_ok=True)


def tagged(items):
    return {
        str(item.get('tag') or ''): item
        for item in items or []
        if isinstance(item, dict) and item.get('tag')
    }


def clients_by_email(inbound):
    settings = inbound.get('settings') if isinstance(inbound, dict) else {}
    clients = settings.get('clients') if isinstance(settings, dict) else []
    return {
        str(client.get('email') or '').strip().lower(): client
        for client in clients or []
        if isinstance(client, dict) and str(client.get('email') or '').strip()
    }


def without_clients(inbound):
    value = copy.deepcopy(inbound)
    settings = value.get('settings') if isinstance(value, dict) else None
    if isinstance(settings, dict) and 'clients' in settings:
        settings['clients'] = []
    return value


def validate_dynamic_sections(source, target):
    ignored = {'inbounds', 'outbounds', 'routing'}
    source_common = {key: value for key, value in source.items() if key not in ignored}
    target_common = {key: value for key, value in target.items() if key not in ignored}
    if source_common != target_common:
        raise DynamicUnsupported('存在 Handler/Routing API 无法热更新的配置段')

    source_inbounds = tagged(source.get('inbounds'))
    target_inbounds = tagged(target.get('inbounds'))
    if source_inbounds.get('api') != target_inbounds.get('api'):
        raise DynamicUnsupported('Xray API 入站发生变化')


def sync_client_changes(tag, source_inbound, target_inbound):
    source_clients = clients_by_email(source_inbound)
    target_clients = clients_by_email(target_inbound)
    affected = {
        email
        for email in set(source_clients) | set(target_clients)
        if source_clients.get(email) != target_clients.get(email)
    }
    if not affected:
        return

    current = runtime_emails(tag)
    remove_keys = {
        email
        for email in affected
        if email in current and (email not in target_clients or source_clients.get(email) != target_clients.get(email))
    }
    remove_values = [
        str((source_clients.get(email) or target_clients.get(email) or {}).get('email') or email)
        for email in sorted(remove_keys)
    ]
    remove_users(tag, remove_values)
    if remove_keys:
        current = wait_runtime_email_state(tag, set(), remove_keys)

    add_keys = {
        email
        for email in affected
        if email in target_clients and email not in current
    }
    add_values = [
        copy.deepcopy(target_clients[email])
        for email in sorted(add_keys)
    ]
    add_users(target_inbound, add_values)
    if add_keys:
        wait_runtime_email_state(tag, add_keys, set())


def apply_runtime_transition(source, target):
    validate_dynamic_sections(source, target)

    source_outbounds = tagged(source.get('outbounds'))
    target_outbounds = tagged(target.get('outbounds'))
    added_outbound_tags = set(target_outbounds) - set(source_outbounds)
    removed_outbound_tags = set(source_outbounds) - set(target_outbounds)
    modified_outbound_tags = {
        tag for tag in set(source_outbounds) & set(target_outbounds)
        if source_outbounds[tag] != target_outbounds[tag]
    }

    source_inbounds = tagged(source.get('inbounds'))
    target_inbounds = tagged(target.get('inbounds'))
    added_inbound_tags = set(target_inbounds) - set(source_inbounds)
    removed_inbound_tags = set(source_inbounds) - set(target_inbounds)
    client_only_tags = set()
    modified_inbound_tags = set()
    for tag in set(source_inbounds) & set(target_inbounds):
        if source_inbounds[tag] == target_inbounds[tag]:
            continue
        if without_clients(source_inbounds[tag]) == without_clients(target_inbounds[tag]):
            client_only_tags.add(tag)
        else:
            modified_inbound_tags.add(tag)
    if 'api' in removed_inbound_tags | modified_inbound_tags:
        raise DynamicUnsupported('不允许动态移除或替换 Xray API 入站')

    current_outbounds = runtime_tags('lso', 'outbounds')
    add_handlers(
        'outbounds',
        'ado',
        [target_outbounds[tag] for tag in sorted(added_outbound_tags) if tag not in current_outbounds],
    )
    for tag in sorted(modified_outbound_tags):
        if tag in current_outbounds:
            remove_handlers('rmo', {tag})
        add_handlers('outbounds', 'ado', [target_outbounds[tag]])

    current_inbounds = runtime_tags('lsi', 'inbounds')
    add_handlers(
        'inbounds',
        'adi',
        [target_inbounds[tag] for tag in sorted(added_inbound_tags) if tag not in current_inbounds],
    )
    for tag in sorted(modified_inbound_tags):
        if tag in current_inbounds:
            remove_handlers('rmi', {tag})
        add_handlers('inbounds', 'adi', [target_inbounds[tag]])

    for tag in sorted(client_only_tags):
        sync_client_changes(tag, source_inbounds[tag], target_inbounds[tag])

    if source.get('routing') != target.get('routing'):
        replace_routing(target.get('routing') or {})

    current_inbounds = runtime_tags('lsi', 'inbounds')
    remove_handlers('rmi', removed_inbound_tags & current_inbounds)
    current_outbounds = runtime_tags('lso', 'outbounds')
    remove_handlers('rmo', removed_outbound_tags & current_outbounds)

    verified_inbounds = runtime_tags('lsi', 'inbounds')
    verified_outbounds = runtime_tags('lso', 'outbounds')
    expected_inbounds = added_inbound_tags | modified_inbound_tags
    expected_outbounds = added_outbound_tags | modified_outbound_tags
    if not expected_inbounds.issubset(verified_inbounds) or removed_inbound_tags & verified_inbounds:
        raise RuntimeError('Xray 动态入站状态未收敛')
    if not expected_outbounds.issubset(verified_outbounds) or removed_outbound_tags & verified_outbounds:
        raise RuntimeError('Xray 动态出站状态未收敛')

    for tag in sorted(client_only_tags):
        source_clients = clients_by_email(source_inbounds[tag])
        target_clients = clients_by_email(target_inbounds[tag])
        affected = {
            email
            for email in set(source_clients) | set(target_clients)
            if source_clients.get(email) != target_clients.get(email)
        }
        wait_runtime_email_state(
            tag,
            {email for email in affected if email in target_clients},
            {email for email in affected if email not in target_clients},
        )


def build_desired_config():
    state = ixr_apply.normalize_state(ixr_apply.read_json(ixr_apply.STATE, None) or ixr_apply.default_state())
    if not state.get('ports'):
        state = ixr_apply.normalize_state(ixr_apply.default_state())
    outbounds = ixr_apply.discover_outbounds()
    if not outbounds:
        raise RuntimeError('未配置 IXR 自管出口')
    return ixr_apply.build_config(
        state,
        outbounds,
        ixr_apply.active_ixr_port_assignments(),
        ixr_apply.read_json(ixr_apply.IX_LEGACY, {}) or {},
        ixr_apply.active_ix_assignments(),
        {},
    )


def validate_config(config):
    path = temporary_json(config)
    try:
        run([XRAY, 'run', '-test', '-config', str(path)], timeout=60)
    finally:
        path.unlink(missing_ok=True)


def install_config(config):
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    if XRAY_CONFIG.exists():
        profile = XRAY_CONFIG.stat()
        mode = profile.st_mode & 0o777
        uid = profile.st_uid
        gid = profile.st_gid
    else:
        mode, uid, gid = 0o644, 0, 0
    descriptor, name = tempfile.mkstemp(prefix='.config.json.ixr-admin-', dir=str(XRAY_CONFIG.parent))
    temporary = Path(name)
    try:
        payload = (json.dumps(config, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, XRAY_CONFIG)
    finally:
        temporary.unlink(missing_ok=True)


def service_active():
    return run(['systemctl', 'is-active', '--quiet', XRAY_SERVICE], check=False).returncode == 0


def restart_from_disk():
    result = run(['systemctl', 'restart', XRAY_SERVICE], timeout=60, check=False)
    return result.returncode == 0 and service_active()


def smart_apply(reason):
    started_at = int(time.time())
    with file_lock(APPLY_LOCK), file_lock(RUNTIME_LOCK):
        current = ixr_apply.read_json(XRAY_CONFIG, None)
        desired = build_desired_config()
        validate_config(desired)
        if not isinstance(current, dict) or not service_active():
            raise DynamicUnsupported('Xray 当前配置或服务状态不支持动态应用')
        if current == desired:
            write_status('ok', reason, 'no_change', started_at)
            print('OK: Xray 配置无需变更')
            return 0
        validate_dynamic_sections(current, desired)
        ensure_dynamic_routing_supported(current, desired)
        runtime_tags('lso', 'outbounds')

        try:
            apply_runtime_transition(current, desired)
            install_config(desired)
        except Exception as error:
            rollback_error = None
            try:
                apply_runtime_transition(desired, current)
            except Exception as caught:
                rollback_error = caught
            if rollback_error is not None and not restart_from_disk():
                write_status('failed', reason, 'dynamic', started_at, f'{error}; rollback={rollback_error}')
                raise RuntimeError(f'动态应用失败且运行态恢复失败：{error}; {rollback_error}')
            write_status('failed', reason, 'dynamic', started_at, str(error))
            raise

        write_status('ok', reason, 'dynamic', started_at)
        print('OK: Xray Handler/Routing 动态应用完成，服务未重启')
        return 0


def full_apply(reason, fallback_reason):
    started_at = int(time.time())
    print(f'FALLBACK: {fallback_reason}', file=sys.stderr)
    with file_lock(APPLY_LOCK), file_lock(RUNTIME_LOCK):
        result = run([FULL_APPLY], timeout=300, check=False)
    if result.stdout:
        print(result.stdout, end='')
    write_status(
        'ok' if result.returncode == 0 else 'failed',
        reason,
        'full_restart',
        started_at,
        '' if result.returncode == 0 else (result.stdout or '')[-1600:],
    )
    return result.returncode


def api_self_test():
    with file_lock(APPLY_LOCK), file_lock(RUNTIME_LOCK):
        current = ixr_apply.read_json(XRAY_CONFIG, None)
        if not isinstance(current, dict) or not service_active():
            raise RuntimeError('Xray 服务或配置不可用')
        target = copy.deepcopy(current)
        stamp = str(int(time.time()))
        outbound_tag = f'codex-admin-selftest-out-{stamp}'
        inbound_tag = f'codex-admin-selftest-in-{stamp}'
        rule_tag = f'codex-admin-selftest-rule-{stamp}'
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = int(probe.getsockname()[1])
        target.setdefault('outbounds', []).append({'tag': outbound_tag, 'protocol': 'freedom'})
        seed_email = f'codex-admin-selftest-seed-{stamp}@example.invalid'
        added_email = f'codex-admin-selftest-added-{stamp}@example.invalid'
        target.setdefault('inbounds', []).append({
            'tag': inbound_tag,
            'listen': '127.0.0.1',
            'port': port,
            'protocol': 'vmess',
            'settings': {'clients': [{
                'id': str(uuid.uuid4()),
                'level': 0,
                'email': seed_email,
            }]},
            'streamSettings': {'network': 'tcp'},
        })
        target.setdefault('routing', {}).setdefault('rules', []).append({
            'type': 'field',
            'inboundTag': [inbound_tag],
            'outboundTag': outbound_tag,
            'ruleTag': rule_tag,
        })
        target_with_user = copy.deepcopy(target)
        target_with_user['inbounds'][-1]['settings']['clients'].append({
            'id': str(uuid.uuid4()),
            'level': 0,
            'email': added_email,
        })
        pid_before = run(['systemctl', 'show', '-p', 'MainPID', '--value', XRAY_SERVICE]).stdout.strip()
        try:
            apply_runtime_transition(current, target)
            apply_runtime_transition(target, target_with_user)
            apply_runtime_transition(target_with_user, target)
            apply_runtime_transition(target, current)
        except Exception:
            try:
                apply_runtime_transition(target_with_user, current)
            except Exception:
                restart_from_disk()
            raise
        pid_after = run(['systemctl', 'show', '-p', 'MainPID', '--value', XRAY_SERVICE]).stdout.strip()
        if pid_before != pid_after:
            raise RuntimeError('动态 API 自检期间 Xray PID 发生变化')
        print(f'OK: 动态 API 自检通过，Xray PID={pid_after}')
        return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--api-self-test':
        try:
            return api_self_test()
        except Exception as error:
            print(f'ERROR: 动态 API 自检失败：{error}', file=sys.stderr)
            return 1

    reason = ' '.join(sys.argv[1:]).strip()[:400] or 'IX Admin 配置变更'
    try:
        return smart_apply(reason)
    except DynamicUnsupported as error:
        return full_apply(reason, str(error))
    except Exception as error:
        print(f'ERROR: Xray 动态应用失败：{error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
