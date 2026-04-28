#!/usr/bin/env bash
# Husn (حصن) — production server installer.
#
# Installs to /opt/husn, creates a `husn` system user, drops a config
# template at /etc/husn/config.yml, registers systemd units, and (optionally)
# emits an nginx site for $DOMAIN.
#
# Tested on: Ubuntu 22.04+, Debian 12+, Kali, Rocky/Alma 9+.
# Run as root:  sudo ./install.sh

set -euo pipefail

# ---------- 0. preflight
if [[ $EUID -ne 0 ]]; then
  echo "✗ Run as root (sudo $0)"; exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/husn"
CONFIG_DIR="/etc/husn"
LOG_DIR="/var/log/husn"
REPORTS_DIR="/var/log/husn/reports"
SERVICE_USER="husn"
DOMAIN="${HUSN_DOMAIN:-}"
WITH_NGINX="${HUSN_WITH_NGINX:-no}"

echo
echo "  ╭─────────────────────────────────────────╮"
echo "  │   Husn (حصن) — Server Installer         │"
echo "  ╰─────────────────────────────────────────╯"
echo
echo "  Repo:    $REPO_ROOT"
echo "  Install: $INSTALL_DIR"
echo "  Config:  $CONFIG_DIR/config.yml"
echo "  Domain:  ${DOMAIN:-<not set — pass HUSN_DOMAIN=foo.bar>}"
echo "  Nginx:   $WITH_NGINX"
echo

# ---------- 1. detect distro + install packages
. /etc/os-release
case "${ID}" in
  ubuntu|debian|kali)
    apt-get update
    apt-get install -y python3 python3-venv python3-pip \
                       git libcap2-bin libpcap-dev iptables curl ca-certificates
    ;;
  fedora|centos|rhel|rocky|almalinux)
    dnf install -y python3 python3-pip git libcap libpcap iptables curl ca-certificates
    ;;
  arch|manjaro)
    pacman -Sy --noconfirm python python-pip git libcap libpcap iptables curl
    ;;
  *)
    echo "⚠ Unrecognised distro '${ID}'."
    echo "  Install manually: python3 (3.9+), nodejs (18+), npm, git, iptables, libpcap-dev, libcap2-bin"
    echo "  Then re-run this script — it'll skip the apt/dnf step and continue."
    ;;
esac

# ---------- 1b. ensure Node.js >= 18 (required by Vite 8 + React 19)
NODE_MAJOR=0
if command -v node >/dev/null 2>&1; then
  NODE_MAJOR=$(node -p "process.versions.node.split('.')[0]" 2>/dev/null || echo 0)
fi
if [[ "$NODE_MAJOR" -lt 18 ]]; then
  echo "Installing Node.js 20 LTS via NodeSource (current: ${NODE_MAJOR:-none}, need 18+)..."
  case "${ID}" in
    ubuntu|debian|kali)
      curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
      apt-get install -y nodejs
      ;;
    fedora|centos|rhel|rocky|almalinux)
      curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
      dnf install -y nodejs
      ;;
    arch|manjaro)
      pacman -Sy --noconfirm nodejs npm
      ;;
    *)
      echo "✗ Node.js 18+ required. Install from https://nodejs.org or your distro and re-run."
      exit 1
      ;;
  esac
fi
echo "✓ node $(node --version)  npm $(npm --version)  python3 $(python3 --version)"

# ---------- 1c. python version sanity check
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,9) else 0)')
if [[ "$PY_OK" != "1" ]]; then
  echo "✗ Python 3.9+ required (found $(python3 --version))."
  echo "  On RHEL 8 / older systems: 'dnf install -y python3.11' then re-run."
  exit 1
fi

# ---------- 2. create service user
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --shell /usr/sbin/nologin --home "$INSTALL_DIR" "$SERVICE_USER"
fi

# ---------- 3. copy code
mkdir -p "$INSTALL_DIR"
rsync -a --delete \
  --exclude '.git' --exclude 'venv' --exclude 'node_modules' \
  --exclude '__pycache__' --exclude 'frontend/dist' \
  "$REPO_ROOT"/ "$INSTALL_DIR"/

# ---------- 4. python venv + deps
python3 -m venv "$INSTALL_DIR/backend/venv"
"$INSTALL_DIR/backend/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/backend/venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt"

# Train models / generate data on first install (idempotent).
( cd "$INSTALL_DIR/backend" && PYTHONPATH=. ./venv/bin/python -m husn.src.ai.data_gen )
( cd "$INSTALL_DIR/backend" && PYTHONPATH=. ./venv/bin/python -m husn.src.ai.model )

# ---------- 5. frontend build
( cd "$INSTALL_DIR/frontend" && npm ci --no-bin-links && npm run build )

# ---------- 6. config + log dirs
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$REPORTS_DIR"
if [[ ! -f "$CONFIG_DIR/config.yml" ]]; then
  cp "$INSTALL_DIR/config/config.example.yml" "$CONFIG_DIR/config.yml"
  if [[ -n "$DOMAIN" ]]; then
    sed -i "s|^domain: .*|domain: $DOMAIN|" "$CONFIG_DIR/config.yml"
  fi
  echo "✓ Wrote $CONFIG_DIR/config.yml — edit it before starting services."
else
  echo "✓ Keeping existing $CONFIG_DIR/config.yml"
fi
chown -R "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_DIR" "$LOG_DIR" "$INSTALL_DIR"
chmod 640 "$CONFIG_DIR/config.yml"

# ---------- 7. raw-socket capabilities for Scapy
PY_BIN="$INSTALL_DIR/backend/venv/bin/python3"
[[ -L "$PY_BIN" ]] && PY_BIN="$(readlink -f "$PY_BIN")"
setcap cap_net_raw,cap_net_admin=eip "$PY_BIN" || \
  echo "⚠ setcap failed — Scapy will need sudo (or run service as root)."

# ---------- 8. systemd units
install -m 644 "$INSTALL_DIR/deploy/husn-backend.service"  /etc/systemd/system/
install -m 644 "$INSTALL_DIR/deploy/husn-frontend.service" /etc/systemd/system/
install -m 644 "$INSTALL_DIR/deploy/husn-vuln.service"     /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now husn-backend.service
systemctl enable --now husn-frontend.service
systemctl enable --now husn-vuln.service

# ---------- 9. nginx (optional)
if [[ "$WITH_NGINX" == "yes" && -n "$DOMAIN" ]]; then
  apt-get install -y nginx || dnf install -y nginx || true
  sed "s|__DOMAIN__|$DOMAIN|g" "$INSTALL_DIR/deploy/nginx-husn.conf" > /etc/nginx/sites-available/husn.conf
  ln -sf /etc/nginx/sites-available/husn.conf /etc/nginx/sites-enabled/husn.conf
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx
  echo
  echo "  Run certbot to enable HTTPS:"
  echo "      sudo certbot --nginx -d $DOMAIN"
fi

# ---------- done
echo
echo "  ╭─────────────────────────────────────────╮"
echo "  │   ✓ Husn installed.                     │"
echo "  ╰─────────────────────────────────────────╯"
echo
echo "  Edit:    sudo nano $CONFIG_DIR/config.yml"
echo "  SMTP:    set HUSN_SMTP_PASSWORD env var (see deploy/husn-backend.service.d/)"
echo "  CLI:     sudo -u $SERVICE_USER $INSTALL_DIR/backend/venv/bin/python -m husn.src.cli"
echo "  Logs:    journalctl -u husn-backend -f"
echo "  Status:  systemctl status husn-backend husn-frontend"
echo
