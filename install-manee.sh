#!/usr/bin/env bash
# ============================================================================
#  Manee · منيع — Universal Installer
# ============================================================================
#
#  Auto-detects the OS, installs every dependency, builds the Python venv,
#  builds the React frontend, registers systemd units (or falls back to a
#  bare init script on non-systemd systems), grants capabilities for raw
#  packet capture + iptables, drops a config template, and starts the
#  three Manee services.
#
#  Supported distros (auto-detected via /etc/os-release):
#    Debian family : Ubuntu 20.04+, Debian 11+, Kali, Linux Mint
#    RHEL family   : Fedora 36+, Rocky 9+, Alma 9+, CentOS Stream 9+, RHEL 9+
#    Arch family   : Arch, Manjaro, EndeavourOS
#    Alpine        : 3.18+
#    macOS         : Apple Silicon + Intel (with Homebrew)
#
#  Usage:
#    sudo bash install-manee.sh
#
#  Optional environment overrides:
#    MANEE_DOMAIN=foo.bar              # for nginx HTTPS config
#    MANEE_WITH_NGINX=yes              # set up nginx reverse proxy
#    MANEE_INSTALL_DIR=/opt/husn       # change install location
#    MANEE_SERVICE_USER=husn           # change service user
#    MANEE_SKIP_BUILD=1                # skip frontend build (use existing dist/)
#    MANEE_SKIP_TRAIN=1                # skip AI model bootstrap (faster reinstall)
#    MANEE_NONINTERACTIVE=1            # don't prompt for anything
#
# ============================================================================

set -euo pipefail

# ────────────────────── colors / pretty output ──────────────────────────────
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  C_BOLD=$(tput bold); C_DIM=$(tput dim); C_RESET=$(tput sgr0)
  C_RED=$(tput setaf 1); C_GREEN=$(tput setaf 2); C_YELLOW=$(tput setaf 3)
  C_BLUE=$(tput setaf 4); C_CYAN=$(tput setaf 6)
else
  C_BOLD=""; C_DIM=""; C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

step() { printf "\n${C_BLUE}${C_BOLD}▸ %s${C_RESET}\n" "$1"; }
ok()   { printf "${C_GREEN}✓${C_RESET} %s\n" "$1"; }
warn() { printf "${C_YELLOW}⚠${C_RESET} %s\n" "$1"; }
err()  { printf "${C_RED}✗${C_RESET} %s\n" "$1" 1>&2; }
die()  { err "$1"; exit 1; }
ask()  { # ask "prompt" "default"  → echoes user's answer
  local prompt="$1" default="${2:-}"
  if [[ "${MANEE_NONINTERACTIVE:-0}" == "1" ]]; then
    echo "$default"; return
  fi
  local ans
  if [[ -n "$default" ]]; then read -p "$prompt [$default]: " ans
  else                          read -p "$prompt: " ans
  fi
  echo "${ans:-$default}"
}

# ────────────────────── pre-flight checks ───────────────────────────────────
banner() {
  cat <<'EOF'

  ███╗   ███╗ █████╗ ███╗   ██╗███████╗███████╗
  ████╗ ████║██╔══██╗████╗  ██║██╔════╝██╔════╝
  ██╔████╔██║███████║██╔██╗ ██║█████╗  █████╗
  ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══╝  ██╔══╝
  ██║ ╚═╝ ██║██║  ██║██║ ╚████║███████╗███████╗
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

         منيع — Intelligent Cyber Defense
              Universal Installer
EOF
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "Run as root: sudo bash $0"
  fi
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ────────────────────── OS detection ────────────────────────────────────────
detect_os() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    OS_FAMILY="macos"; OS_ID="macos"; OS_VER="$(sw_vers -productVersion)"
    PKG_MGR="brew"
    return
  fi
  if [[ ! -r /etc/os-release ]]; then
    die "Can't detect OS — /etc/os-release missing"
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_VER="${VERSION_ID:-?}"
  case "$OS_ID" in
    ubuntu|debian|kali|linuxmint|raspbian|pop)
      OS_FAMILY="debian"; PKG_MGR="apt-get" ;;
    fedora|rhel|centos|rocky|almalinux|amzn)
      OS_FAMILY="rhel"; PKG_MGR=$(command -v dnf >/dev/null && echo dnf || echo yum) ;;
    arch|manjaro|endeavouros|garuda)
      OS_FAMILY="arch"; PKG_MGR="pacman" ;;
    alpine)
      OS_FAMILY="alpine"; PKG_MGR="apk" ;;
    *)
      OS_FAMILY="unknown"; PKG_MGR="unknown" ;;
  esac
}

# ────────────────────── package install ─────────────────────────────────────
install_packages() {
  step "Installing system packages (family: $OS_FAMILY)"
  case "$OS_FAMILY" in
    debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y --no-install-recommends \
          python3 python3-venv python3-pip python3-dev \
          git curl ca-certificates \
          libcap2-bin libpcap-dev iptables \
          build-essential pkg-config
      ;;
    rhel)
      $PKG_MGR install -y \
          python3 python3-pip python3-devel \
          git curl ca-certificates \
          libcap libpcap-devel iptables \
          gcc make pkgconfig
      ;;
    arch)
      pacman -Sy --noconfirm --needed \
          python python-pip git curl ca-certificates \
          libcap libpcap iptables base-devel pkgconf
      ;;
    alpine)
      apk add --no-cache \
          python3 py3-pip python3-dev \
          git curl ca-certificates \
          libcap libpcap-dev iptables \
          build-base pkgconfig
      ;;
    macos)
      command -v brew >/dev/null || die "Homebrew required on macOS — install from https://brew.sh"
      brew install python@3.11 node@20 git libpcap || true
      warn "macOS doesn't have iptables — Manee will run in simulated-block mode only"
      ;;
    *)
      warn "Unknown OS family — install manually: python3 (3.9+), git, libpcap-dev, libcap, iptables"
      warn "Then re-run this script and it'll skip the package step."
      ;;
  esac
  ok "System packages ready"
}

# ────────────────────── Node.js (need >= 18 for Vite 8 + React 19) ──────────
install_node() {
  step "Checking Node.js"
  local node_major=0
  if command -v node >/dev/null 2>&1; then
    node_major=$(node -p "process.versions.node.split('.')[0]" 2>/dev/null || echo 0)
  fi
  if (( node_major >= 18 )); then
    ok "Node.js $(node --version) — already adequate"
    return
  fi

  warn "Node.js >= 18 required (current: ${node_major:-none}). Installing 20 LTS..."
  case "$OS_FAMILY" in
    debian)
      curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
      apt-get install -y nodejs
      ;;
    rhel)
      curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
      $PKG_MGR install -y nodejs
      ;;
    arch)     pacman -Sy --noconfirm --needed nodejs npm ;;
    alpine)   apk add --no-cache nodejs npm ;;
    macos)    brew install node@20 ;;
    *)        die "Install Node.js >= 18 manually from https://nodejs.org" ;;
  esac
  ok "Node.js $(node --version) installed"
}

# ────────────────────── Python sanity ───────────────────────────────────────
check_python() {
  step "Verifying Python"
  command -v python3 >/dev/null || die "python3 not found after install — please report"
  local py_ok
  py_ok=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,9) else 0)')
  if [[ "$py_ok" != "1" ]]; then
    die "Python 3.9+ required (found $(python3 --version)). On RHEL 8: dnf install -y python3.11 then re-run."
  fi
  ok "Python $(python3 --version | awk '{print $2}')"
}

# ────────────────────── Service user ────────────────────────────────────────
SERVICE_USER="${MANEE_SERVICE_USER:-husn}"

create_user() {
  step "Service user ($SERVICE_USER)"
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    ok "User $SERVICE_USER already exists"
    return
  fi
  case "$OS_FAMILY" in
    macos)
      warn "macOS — skipping service-user creation (running as root for development)"
      ;;
    *)
      useradd --system --shell /usr/sbin/nologin --home "$INSTALL_DIR" "$SERVICE_USER"
      ok "Created system user $SERVICE_USER"
      ;;
  esac
}

# ────────────────────── Copy code ───────────────────────────────────────────
INSTALL_DIR="${MANEE_INSTALL_DIR:-/opt/husn}"
CONFIG_DIR="/etc/husn"
LOG_DIR="/var/log/husn"
REPORTS_DIR="/var/log/husn/reports"
BACKUP_DIR="/etc/husn/backups"

stage_code() {
  step "Staging code at $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  rsync -a --delete \
    --exclude '.git' --exclude 'venv' --exclude 'node_modules' \
    --exclude '__pycache__' --exclude 'frontend/dist' \
    --exclude 'backend/reports' --exclude 'logs' \
    "$REPO_ROOT"/ "$INSTALL_DIR"/
  ok "Code staged"
}

# ────────────────────── Python venv + deps ──────────────────────────────────
build_venv() {
  step "Python virtualenv + dependencies"
  python3 -m venv "$INSTALL_DIR/backend/venv"
  # Use /var/tmp for staging (some VPS templates have tiny /tmp tmpfs)
  TMPDIR=/var/tmp "$INSTALL_DIR/backend/venv/bin/pip" install \
    --upgrade --no-cache-dir pip wheel setuptools
  TMPDIR=/var/tmp "$INSTALL_DIR/backend/venv/bin/pip" install \
    --no-cache-dir -r "$INSTALL_DIR/backend/requirements.txt"
  ok "Python deps installed"
}

# ────────────────────── AI model bootstrap ──────────────────────────────────
bootstrap_ai() {
  if [[ "${MANEE_SKIP_TRAIN:-0}" == "1" ]]; then
    warn "MANEE_SKIP_TRAIN=1 set — skipping AI model bootstrap"; return
  fi
  step "Bootstrapping AI models (one-time, ~30s)"
  ( cd "$INSTALL_DIR/backend" && PYTHONPATH=. ./venv/bin/python -m husn.src.ai.data_gen )
  ( cd "$INSTALL_DIR/backend" && PYTHONPATH=. ./venv/bin/python -m husn.src.ai.model )
  ok "Models trained + persisted"
}

# ────────────────────── Frontend build ──────────────────────────────────────
build_frontend() {
  if [[ "${MANEE_SKIP_BUILD:-0}" == "1" ]]; then
    warn "MANEE_SKIP_BUILD=1 — skipping frontend build (using existing dist/)"
    return
  fi
  step "Building frontend (Vite production build)"
  ( cd "$INSTALL_DIR/frontend" && npm ci --no-bin-links && npm run build )
  ok "Frontend bundle ready at $INSTALL_DIR/frontend/dist"
}

# ────────────────────── Config + log dirs ───────────────────────────────────
setup_dirs() {
  step "Creating state directories"
  mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$REPORTS_DIR" "$BACKUP_DIR"
  if [[ ! -f "$CONFIG_DIR/config.yml" ]]; then
    cp "$INSTALL_DIR/config/config.example.yml" "$CONFIG_DIR/config.yml"
    if [[ -n "${MANEE_DOMAIN:-}" ]]; then
      sed -i "s|^domain: .*|domain: $MANEE_DOMAIN|" "$CONFIG_DIR/config.yml"
    fi
    ok "Wrote $CONFIG_DIR/config.yml — edit it to add SMTP / DeepSeek details"
  else
    ok "Existing $CONFIG_DIR/config.yml preserved"
  fi

  case "$OS_FAMILY" in
    macos) chown -R "$(whoami):staff" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" 2>/dev/null || true ;;
    *)     chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" ;;
  esac
  chmod 640 "$CONFIG_DIR/config.yml"
  ok "Permissions set"
}

# ────────────────────── Capabilities (raw sockets + iptables) ───────────────
grant_caps() {
  step "Granting raw-socket + iptables capabilities"
  case "$OS_FAMILY" in
    macos)
      warn "macOS — capabilities not applicable. Sniffer will need sudo or System Preferences → Privacy → Full Disk Access"
      return
      ;;
    *)
      if ! command -v setcap >/dev/null 2>&1; then
        warn "setcap not found — skipping. Sniffer will need sudo to capture packets."
        return
      fi
      local py_bin="$INSTALL_DIR/backend/venv/bin/python3"
      [[ -L "$py_bin" ]] && py_bin=$(readlink -f "$py_bin")
      if setcap cap_net_raw,cap_net_admin=eip "$py_bin"; then
        ok "Granted CAP_NET_RAW + CAP_NET_ADMIN to $py_bin"
      else
        warn "setcap failed — Manee will run sniffer + iptables in degraded mode"
      fi
      ;;
  esac
}

# ────────────────────── systemd or fallback init ────────────────────────────
register_services() {
  step "Registering services"
  if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /etc/systemd/system ]]; then
    warn "systemd not available — falling back to a manual start script"
    cat > "$INSTALL_DIR/start-manee.sh" <<'STARTUP'
#!/usr/bin/env bash
# Bare start script for non-systemd hosts (Alpine OpenRC, macOS dev, Docker)
set -e
cd "$(dirname "$0")"
HUSN_CONFIG=/etc/husn/config.yml \
PYTHONPATH=backend \
backend/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir backend &
backend/venv/bin/python -m uvicorn vuln_app:app --host 127.0.0.1 --port 9000 --app-dir backend &
cd frontend && python3 -m http.server 5173 --directory dist &
wait
STARTUP
    chmod +x "$INSTALL_DIR/start-manee.sh"
    ok "Bare start script: $INSTALL_DIR/start-manee.sh (run it manually)"
    return
  fi

  install -m 644 "$INSTALL_DIR/deploy/husn-backend.service"  /etc/systemd/system/
  install -m 644 "$INSTALL_DIR/deploy/husn-frontend.service" /etc/systemd/system/
  install -m 644 "$INSTALL_DIR/deploy/husn-vuln.service"     /etc/systemd/system/

  # Drop-in for the writable state dirs (tightened ProtectSystem=strict
  # would otherwise refuse autopatch backups + runtime YAML writes).
  mkdir -p /etc/systemd/system/husn-backend.service.d
  cat > /etc/systemd/system/husn-backend.service.d/manee-paths.conf <<EOF
[Service]
ReadWritePaths=$INSTALL_DIR $CONFIG_DIR $LOG_DIR
EOF

  systemctl daemon-reload
  systemctl enable --now husn-backend.service
  systemctl enable --now husn-frontend.service
  systemctl enable --now husn-vuln.service
  ok "All three services registered + started"
}

# ────────────────────── nginx (optional) ────────────────────────────────────
setup_nginx() {
  if [[ "${MANEE_WITH_NGINX:-no}" != "yes" ]] || [[ -z "${MANEE_DOMAIN:-}" ]]; then
    return
  fi
  step "Setting up nginx for ${MANEE_DOMAIN}"
  case "$OS_FAMILY" in
    debian) apt-get install -y nginx ;;
    rhel)   $PKG_MGR install -y nginx ;;
    arch)   pacman -Sy --noconfirm --needed nginx ;;
    *)      warn "nginx auto-install unsupported on $OS_FAMILY — install + configure manually"; return ;;
  esac
  sed "s|__DOMAIN__|$MANEE_DOMAIN|g" "$INSTALL_DIR/deploy/nginx-husn.conf" \
    > /etc/nginx/sites-available/manee.conf 2>/dev/null \
    || sed "s|__DOMAIN__|$MANEE_DOMAIN|g" "$INSTALL_DIR/deploy/nginx-husn.conf" \
       > /etc/nginx/conf.d/manee.conf
  [[ -d /etc/nginx/sites-enabled ]] && ln -sf /etc/nginx/sites-available/manee.conf /etc/nginx/sites-enabled/manee.conf
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx
  ok "nginx site enabled — run 'sudo certbot --nginx -d $MANEE_DOMAIN' for HTTPS"
}

# ────────────────────── Health check ────────────────────────────────────────
health_check() {
  step "Health check (waiting 5s for services to settle)"
  sleep 5
  if [[ "$OS_FAMILY" == "macos" ]]; then
    warn "macOS — manual start required: bash $INSTALL_DIR/start-manee.sh"
    return
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemd not present — start manually: bash $INSTALL_DIR/start-manee.sh"
    return
  fi
  for svc in husn-backend husn-frontend husn-vuln; do
    if systemctl is-active --quiet "$svc"; then
      ok "$svc is running"
    else
      warn "$svc is NOT running — check: journalctl -u $svc --no-pager -n 20"
    fi
  done
  if curl -sf -o /dev/null http://localhost:8000/healthz 2>/dev/null \
     || curl -sf -o /dev/null http://localhost:8000/status 2>/dev/null; then
    ok "Backend reachable on http://localhost:8000"
  else
    warn "Backend not responding yet — give it 10s and curl manually"
  fi
}

# ────────────────────── Final instructions ──────────────────────────────────
final_message() {
  cat <<EOF

${C_GREEN}${C_BOLD}╭─────────────────────────────────────────────────────╮${C_RESET}
${C_GREEN}${C_BOLD}│   ✓ Manee installed.                                │${C_RESET}
${C_GREEN}${C_BOLD}╰─────────────────────────────────────────────────────╯${C_RESET}

  ${C_BOLD}Detected${C_RESET}      : $OS_ID $OS_VER ($OS_FAMILY family)
  ${C_BOLD}Installed at${C_RESET}  : $INSTALL_DIR
  ${C_BOLD}Config${C_RESET}        : $CONFIG_DIR/config.yml
  ${C_BOLD}Logs${C_RESET}          : journalctl -u husn-backend -f
  ${C_BOLD}Backend port${C_RESET}  : http://localhost:8000
  ${C_BOLD}Frontend port${C_RESET} : http://localhost:5173
  ${C_BOLD}Vuln target${C_RESET}   : http://localhost:9000

  ${C_CYAN}${C_BOLD}Required next steps:${C_RESET}

  1. Set the DeepSeek API key (for chat + auto patch + reports):
     ${C_DIM}sudo systemctl edit husn-backend
     [Service]
     Environment=HUSN_DEEPSEEK_KEY=sk-...${C_RESET}

  2. Set the SMTP password (for email alerts):
     ${C_DIM}# Same drop-in file:
     Environment=HUSN_SMTP_PASSWORD=YOUR_PASSWORD${C_RESET}

  3. Edit recipients + (optional) inbox allowlist:
     ${C_DIM}sudo nano $CONFIG_DIR/config.yml${C_RESET}

  4. Restart so the env vars load:
     ${C_DIM}sudo systemctl restart husn-backend${C_RESET}

  5. Sign in at http://localhost:5173 with admin / admin@
     (CHANGE THE PASSWORD IMMEDIATELY)

  6. To enable real iptables blocking (off by default for safety):
     ${C_DIM}sudo sed -i 's/real_iptables: false/real_iptables: true/' \\
                 $CONFIG_DIR/config.yml${C_RESET}
     ${C_YELLOW}⚠ Whitelist your admin IP in /defense/lists FIRST or you'll lock
        yourself out!${C_RESET}

  ${C_BOLD}Uninstall${C_RESET} : sudo bash $INSTALL_DIR/uninstall.sh [--purge]

  منيع · Manee · Defense Grid
EOF
}

# ────────────────────── main ────────────────────────────────────────────────
main() {
  banner
  require_root
  detect_os
  printf "\n${C_BOLD}Detected:${C_RESET} %s %s (family: %s, pkg: %s)\n" \
         "$OS_ID" "$OS_VER" "$OS_FAMILY" "$PKG_MGR"

  if [[ "$OS_FAMILY" == "unknown" ]] && [[ "${MANEE_NONINTERACTIVE:-0}" != "1" ]]; then
    local cont
    cont=$(ask "Continue with manual dependency install? (y/n)" "n")
    [[ "$cont" =~ ^[yY] ]] || die "Aborted."
  fi

  install_packages
  install_node
  check_python
  create_user
  stage_code
  build_venv
  bootstrap_ai
  build_frontend
  setup_dirs
  grant_caps
  register_services
  setup_nginx
  health_check
  final_message
}

main "$@"
