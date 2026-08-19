# IXR

IXR is a small Web manager for an independent Xray router. It manages VMess inbound ports, outbound nodes, smart outbound pools, rule routing, health checks and usage stats.

This is a sanitized source snapshot. It does **not** include real nodes, UUIDs, passwords, runtime logs, Xray binaries or private deployment data.

## Disclaimer

This project is provided for lawful self-hosting, learning, and network management only. Users are solely responsible for how they deploy and use it, including compliance with local laws, service terms, and third-party rights.

## Layout

- `src/ixr-manager/public/index.php` - Web UI
- `src/ixr-manager/public/ix-admin.php` - integrated legacy IX admin page
- `src/ixr-manager/bin/` - IXR apply, health check, usage stats and async helpers
- `src/ixr-manager/data/*.example.json` - safe example configs
- `src/ix-panel/public/` - sanitized legacy IX V2Ray panel
- `deploy/systemd/` - systemd service/timer templates
- `deploy/nginx/` - Nginx site templates
- `scripts/wrappers/` - `/usr/local/bin/ixr-*` wrappers
- `install.sh` - source checkout installer

## Quick install

```bash
sudo IXR_DOMAIN=ixr.example.com   IXR_WEB_PORT=10198   IXR_EXPORT_ADDRESS=proxy.example.com   IXR_ADMIN_USER=admin   IXR_ADMIN_PASSWORD=change-me   bash install.sh
```

Optional DN42 DNS override:

```bash
sudo IXR_DN42_DNS_SERVERS=your-dn42-dns-ip bash install.sh
```

After install, edit:

- `/opt/ixr-manager/data/outbounds.json`
- `/opt/ixr-manager/data/state.json`
- `/opt/ixr-manager/data/export.json`

Then run:

```bash
/usr/local/bin/ixr-apply
/usr/local/bin/ixr-health-check
/usr/local/bin/ixr-usage-stats
```

## Do not commit real values

- Web admin passwords
- VMess UUIDs and imported links
- Private server IPs/domains
- Runtime `health.json`, `usage.json`, `apply_status.json`
- Generated `/usr/local/etc/xray/config.json`

## Legacy IX panel

The legacy IX admin page is integrated into IXR at `/ix-admin.php` and can also be opened from the IXR sidebar through `IX Admin`. It manages the existing 233boy V2Ray files on the same server while IXR continues to manage its independent Xray router separately.

`src/ix-panel/public/` is kept as a sanitized standalone reference copy. Configure secrets and public domains with environment variables or replace the example values during deployment.

Common environment variables:

- `IX_PANEL_ADMIN_USER`
- `IX_PANEL_ADMIN_PASSWORD`
- `IX_PANEL_FRONT_PASSWORD`
- `IX_PANEL_FRONT_ENTRY_HOST`
- `IX_PANEL_PUBLIC_BASE_URL`
- `IX_PANEL_GRAFANA_URL`

When using the integrated `/ix-admin.php` page, login is handled by IXR. The legacy IX admin password variables are only needed for standalone legacy deployments.
