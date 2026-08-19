# Legacy IX panel

`src/ix-panel/public/` contains a sanitized copy of a legacy IX panel. The admin functions are also integrated into IXR at `src/ixr-manager/public/ix-admin.php`.

## Purpose

- Manage an existing 233boy V2Ray configuration.
- Export V2Ray subscription links from the current node list.
- Provide a front page and admin page for legacy deployments.

## Deployment notes

Copy `src/ix-panel/public/` to `/opt/ix-panel/public/`, then use `deploy/nginx/ix-panel.conf.template` as the Nginx site template.

For the integrated IXR deployment, copy `src/ixr-manager/public/ix-admin.php` with the rest of `src/ixr-manager/public/`. The IXR sidebar exposes it as `IX Admin`, and it uses the IXR login session instead of a separate admin login.

Set deployment-specific values outside the repository:

- `IX_PANEL_ADMIN_USER`
- `IX_PANEL_ADMIN_PASSWORD`
- `IX_PANEL_FRONT_PASSWORD`
- `IX_PANEL_FRONT_ENTRY_HOST`
- `IX_PANEL_PUBLIC_BASE_URL`
- `IX_PANEL_GRAFANA_URL`

The integrated `ix-admin.php` page reuses the IXR login session. `IX_PANEL_ADMIN_USER` and `IX_PANEL_ADMIN_PASSWORD` are only used by the standalone legacy copy.

Do not commit real node configuration files, subscription secrets, password hash files, access logs, or generated V2Ray/Xray runtime configs.
