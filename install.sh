#!/usr/bin/env bash
set -Eeuo pipefail
IXR_DOMAIN="${IXR_DOMAIN:-ixr.example.com}"
IXR_WEB_PORT="${IXR_WEB_PORT:-10198}"
IXR_EXPORT_ADDRESS="${IXR_EXPORT_ADDRESS:-proxy.example.com}"
IXR_ADMIN_USER="${IXR_ADMIN_USER:-admin}"
IXR_ADMIN_PASSWORD="${IXR_ADMIN_PASSWORD:-change-me}"
IXR_DN42_DNS_SERVERS="${IXR_DN42_DNS_SERVERS:-}"
INSTALL_DEPS="${INSTALL_DEPS:-1}"
INSTALL_XRAY="${INSTALL_XRAY:-1}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="/root/ixr-install-backups/$(date +%Y%m%d%H%M%S)"
need_root(){ [ "$(id -u)" -eq 0 ] || { echo "Please run as root: sudo bash install.sh" >&2; exit 1; }; }
backup_path(){ local path="$1"; if [ -e "$path" ] || [ -L "$path" ]; then mkdir -p "$BACKUP_DIR$(dirname "$path")"; cp -a "$path" "$BACKUP_DIR$path"; fi; }
install_deps(){ [ "$INSTALL_DEPS" = "1" ] || return 0; if command -v apt-get >/dev/null 2>&1; then export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y python3 curl nginx php-fpm php-cli ca-certificates util-linux procps; fi; }
install_xray(){ if [ "$INSTALL_XRAY" = "1" ] && ! [ -x /usr/local/bin/xray ]; then bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; fi; }
find_php_sock(){ local svc; for svc in $(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1}'); do systemctl enable --now "$svc" >/dev/null 2>&1 || true; systemctl restart "$svc" >/dev/null 2>&1 || true; done; sleep 1; ls /run/php/php*-fpm.sock 2>/dev/null | sort -V | tail -1 || true; }
init_data_file(){ local name="$1"; [ -f "/opt/ixr-manager/data/${name}.json" ] || cp -a "/opt/ixr-manager/data/${name}.example.json" "/opt/ixr-manager/data/${name}.json"; }
patch_runtime_values(){ IXR_DOMAIN="$IXR_DOMAIN" IXR_EXPORT_ADDRESS="$IXR_EXPORT_ADDRESS" IXR_ADMIN_USER="$IXR_ADMIN_USER" IXR_ADMIN_PASSWORD="$IXR_ADMIN_PASSWORD" python3 - <<'PY'
from pathlib import Path
import json, os
index = Path('/opt/ixr-manager/public/index.php')
text = index.read_text(encoding='utf-8')
text = text.replace("getenv('IXR_ADMIN_USER') ?: 'admin'", "getenv('IXR_ADMIN_USER') ?: " + repr(os.environ['IXR_ADMIN_USER']))
text = text.replace("getenv('IXR_ADMIN_PASSWORD') ?: 'change-me'", "getenv('IXR_ADMIN_PASSWORD') ?: " + repr(os.environ['IXR_ADMIN_PASSWORD']))
text = text.replace('/?section=', f"https://{os.environ['IXR_DOMAIN']}/?section=")
index.write_text(text, encoding='utf-8')
export_path = Path('/opt/ixr-manager/data/export.json')
data = json.loads(export_path.read_text(encoding='utf-8'))
data['default_address'] = os.environ['IXR_EXPORT_ADDRESS']
export_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
PY
}
write_runtime_env(){ IXR_DN42_DNS_SERVERS="$IXR_DN42_DNS_SERVERS" python3 - <<'PY'
from pathlib import Path
import os, shlex
Path('/etc/default/ixr-manager').write_text(
    'IXR_DN42_DNS_SERVERS=' + shlex.quote(os.environ['IXR_DN42_DNS_SERVERS']) + '\n',
    encoding='utf-8',
)
PY
}
write_nginx_conf(){ local php_sock="$1"; sed -e "s|\${IXR_DOMAIN}|${IXR_DOMAIN}|g" -e "s|\${IXR_WEB_PORT}|${IXR_WEB_PORT}|g" -e "s|\${PHP_FPM_SOCK}|${php_sock}|g" "$SRC_DIR/deploy/nginx/ixr-manager.conf.template" > /etc/nginx/sites-available/ixr-manager-10198; ln -sf /etc/nginx/sites-available/ixr-manager-10198 /etc/nginx/sites-enabled/ixr-manager-10198; }
main(){
  need_root; install_deps; install_xray; mkdir -p "$BACKUP_DIR"
  systemctl stop ixr-health-check.timer ixr-usage-stats.timer ixr-health-check.service ixr-usage-stats.service xray.service 2>/dev/null || true
  backup_path /opt/ixr-manager; backup_path /etc/nginx/sites-available/ixr-manager-10198; backup_path /etc/default/ixr-manager
  rm -rf /opt/ixr-manager; mkdir -p /opt/ixr-manager /usr/local/bin /etc/systemd/system /usr/local/etc/xray /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/default
  cp -a "$SRC_DIR/src/ixr-manager/bin" "$SRC_DIR/src/ixr-manager/public" "$SRC_DIR/src/ixr-manager/data" /opt/ixr-manager/
  cp -a "$SRC_DIR/scripts/wrappers/ixr-"* /usr/local/bin/
  cp -a "$SRC_DIR/deploy/systemd/"*.service "$SRC_DIR/deploy/systemd/"*.timer /etc/systemd/system/
  chmod 755 /usr/local/bin/ixr-* /opt/ixr-manager/bin/*.py
  chown -R root:www-data /opt/ixr-manager 2>/dev/null || true; chown -R www-data:www-data /opt/ixr-manager/data 2>/dev/null || true
  chmod 775 /opt/ixr-manager/data; find /opt/ixr-manager/data -type f -exec chmod 664 {} \; 2>/dev/null || true
  for n in state outbounds export usage health apply_status usage_baseline; do init_data_file "$n"; done
  patch_runtime_values
  write_runtime_env
  PHP_SOCK="$(find_php_sock)"; [ -n "$PHP_SOCK" ] || { echo "php-fpm socket not found" >&2; exit 1; }
  write_nginx_conf "$PHP_SOCK"
  systemctl daemon-reload; nginx -t; systemctl enable --now nginx
  /usr/local/bin/ixr-apply
  systemctl enable --now xray.service ixr-health-check.timer ixr-usage-stats.timer
  echo "IXR installed: https://${IXR_DOMAIN}/ or http://SERVER_IP:${IXR_WEB_PORT}/"
  echo "Backup: $BACKUP_DIR"
}
main "$@"
