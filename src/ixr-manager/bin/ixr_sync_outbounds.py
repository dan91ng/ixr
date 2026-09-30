#!/usr/bin/env python3
from pathlib import Path

OUTS = Path('/opt/ixr-manager/data/outbounds.json')


def main():
    count = 0
    try:
        import json
        data = json.loads(OUTS.read_text(encoding='utf-8'))
        if isinstance(data, list):
            count = len(data)
    except Exception:
        count = 0
    print('CHANGED=0')
    print('MODE=independent')
    print('MESSAGE=IXR 出口已独立管理，不再从 ix.cloudc.dev / 旧 V2Ray 同步')
    print(f'OUTBOUNDS={count}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
