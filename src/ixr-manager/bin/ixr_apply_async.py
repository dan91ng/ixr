#!/usr/bin/env python3
import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(os.environ.get('IXR_BASE', '/opt/ixr-manager'))
DATA = Path(os.environ.get('IXR_DATA', str(BASE / 'data')))
STATUS = DATA / 'apply_status.json'
LOCK = Path(os.environ.get('IXR_APPLY_ASYNC_LOCK', str(DATA / 'apply.lock')))
APPLY_COMMAND = os.environ.get('IXR_APPLY_COMMAND', '/usr/local/bin/ixr-apply')


def write_status(payload):
    DATA.mkdir(parents=True, exist_ok=True)
    tmp = STATUS.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(tmp, STATUS)
    os.chmod(STATUS, 0o664)
    try:
        shutil.chown(STATUS, 'www-data', 'www-data')
    except Exception:
        pass


def open_lock_file():
    DATA.mkdir(parents=True, exist_ok=True)
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(LOCK, flags, 0o660)
    os.fchmod(descriptor, 0o660)
    try:
        shutil.chown(LOCK, 'www-data', 'www-data')
    except Exception:
        pass
    return os.fdopen(descriptor, 'r+')


def apply_command():
    direct = str(os.environ.get('IXR_APPLY_ASYNC_DIRECT', '')).strip().lower() in {'1', 'true', 'yes'}
    if os.geteuid() == 0 or direct:
        return [APPLY_COMMAND]
    return ['sudo', APPLY_COMMAND]


def main():
    reason = ' '.join(sys.argv[1:]).strip()[:400] or '配置变更'
    started = int(time.time())
    with open_lock_file() as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        write_status({
            'status': 'running',
            'started_at': started,
            'finished_at': 0,
            'code': None,
            'reason': reason,
            'output': '',
        })
        try:
            proc = subprocess.run(
                apply_command(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=240,
            )
            code = proc.returncode
            output = (proc.stdout or '')[-6000:]
        except subprocess.TimeoutExpired as exc:
            code = 124
            output = ((exc.stdout or '') if isinstance(exc.stdout, str) else '').strip()
            output = (output + '\nERROR: ixr-apply timed out after 240s')[-6000:]
        except Exception as exc:
            code = 1
            output = ('ERROR: %s' % exc)[-6000:]
        write_status({
            'status': 'ok' if code == 0 else 'failed',
            'started_at': started,
            'finished_at': int(time.time()),
            'code': code,
            'reason': reason,
            'output': output,
        })
        return code


if __name__ == '__main__':
    raise SystemExit(main())
