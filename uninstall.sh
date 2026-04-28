#!/usr/bin/env bash
# Husn (حصن) — uninstaller.
# Removes systemd units, the install dir, and the service user.
# Preserves /etc/husn/config.yml and /var/log/husn unless --purge is passed.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "✗ Run as root (sudo $0)"; exit 1
fi

PURGE="no"
[[ "${1:-}" == "--purge" ]] && PURGE="yes"

systemctl disable --now husn-backend.service husn-frontend.service 2>/dev/null || true
rm -f /etc/systemd/system/husn-backend.service /etc/systemd/system/husn-frontend.service
systemctl daemon-reload

rm -rf /opt/husn
rm -f /etc/nginx/sites-enabled/husn.conf /etc/nginx/sites-available/husn.conf 2>/dev/null || true

if [[ "$PURGE" == "yes" ]]; then
  rm -rf /etc/husn /var/log/husn
  userdel husn 2>/dev/null || true
  echo "✓ Husn fully purged."
else
  echo "✓ Husn removed. Config and logs kept (run with --purge to wipe them too)."
fi
