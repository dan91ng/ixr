# IXR Manager

IXR Manager is a web management system for an Xray-based independent router. It manages VMess inbound ports, outbound nodes, smart outbound pools, IX/IXR route bindings, users, quotas, subscription links, health checks and usage statistics.

This repository contains a **sanitized source snapshot** generated from the current production codebase. It does not include real users, runtime databases, node credentials, subscription tokens, password hashes, generated Xray configs or private deployment archives.

## Main features

- Unified IX and IXR outbound management.
- VMess inbound and outbound generation for Xray.
- Smart auto pool with health checks and DN42-aware probing.
- User creation, status, expiry time and traffic quota management.
- Per-user IXR port authorization and shared IX route allocation.
- User portal with account status, node list, v2rayN/v2rayNG tutorials and VMess/Surge subscriptions.
- Xray API usage statistics and quota enforcement.
- Admin helpers for applying config asynchronously and syncing runtime users.

## Repository layout

```text
src/ixr-manager/public/       PHP admin/user/subscription pages
src/ixr-manager/public/lib/   shared PHP stores and Xray admin helper
src/ixr-manager/bin/          Python apply, health, usage and sync tasks
src/ixr-manager/migrations/   SQLite schema migrations
src/ixr-manager/data/         safe example JSON files only
deploy/nginx/                 Nginx templates
deploy/systemd/               systemd services and timers
deploy/sudoers/               sudoers rule for controlled admin helper
scripts/wrappers/             /usr/local/bin wrappers
install.sh                    simple installer for a fresh host
```

## Quick install

```bash
sudo IXR_DOMAIN=ixr.example.com \
  IXR_WEB_PORT=10198 \
  IXR_EXPORT_ADDRESS=proxy.example.com \
  IXR_ADMIN_USER=admin \
  IXR_ADMIN_PASSWORD=change-me \
  bash install.sh
```

## Runtime data that must not be committed

Do not commit users databases, password hashes, real runtime JSON files, UUIDs, tokens, generated Xray configs, production backups or logs. `.gitignore` keeps runtime JSON files out of Git except `*.example.json`.

## Development checks

```bash
find src/ixr-manager/public -name '*.php' -print0 | xargs -0 -n1 php -l
python3 -m py_compile src/ixr-manager/bin/*.py
```

## Current source baseline

Source code pulled from the synchronized DE/production IXR deployment. Backup archives are stored outside this repository on the MCP host desktop. This Git tree is sanitized for publication and review.
