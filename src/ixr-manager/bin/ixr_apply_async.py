#!/usr/bin/env python3
import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

DATA = Path('/opt/ixr-manager/data')
STATUS = DATA / 'apply_status.json'
LOCK = Path('/tmp/ixr-apply-async.lock')


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


def main():
    reason = ' '.join(sys.argv[1:]).strip()[:400] or '配置变更'
    started = int(time.time())
    with LOCK.open('w') as lock_file:
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
                ['sudo', '/usr/local/bin/ixr-apply'],
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
