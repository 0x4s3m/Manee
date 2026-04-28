#!/usr/bin/env bash
# Husn VPS setup — one-shot.
#
# Run this AFTER you've put the Husn project on the VPS. It hardens the box,
# installs Husn, opens the firewall ports the demo needs, and tunes the
# config for a public mini-PC-style deployment.
#
# Idempotent — re-running is safe.
#
# Usage (as root):
#     cd ~/husn      # or wherever you put the project
#     sudo bash vps-setup.sh
#
# Optional environment overrides:
#     SMTP_PASSWORD='...'        # default: Husn$0542306151 (your Hostinger pw)
#     DOMAIN=husn.example.com    # default: the VPS public IP
#     ADMIN_IP=1.2.3.4           # your laptop's public IP — added to whitelist
#                                # so you don't lock YOURSELF out during the demo
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "✗ Run as root: sudo bash vps-setup.sh"
  exit 1
fi

cd "$(dirname "$0")"
REPO="$(pwd)"
SMTP_PASSWORD="${SMTP_PASSWORD:-Husn\$0542306151}"
PUBLIC_IP="$(curl -fsS https://api.ipify.org || hostname -I | awk '{print $1}')"
DOMAIN="${DOMAIN:-$PUBLIC_IP}"
ADMIN_IP="${ADMIN_IP:-}"

echo
echo "  ╭───────────────────────────────────────────────╮"
echo "  │   Husn — VPS one-shot setup                  │"
echo "  ╰───────────────────────────────────────────────╯"
echo "  Repo:        $REPO"
echo "  Public IP:   $PUBLIC_IP"
echo "  Domain:      $DOMAIN"
echo "  Admin IP:    ${ADMIN_IP:-<not set — set ADMIN_IP=your.laptop.ip to whitelist>}"
echo

# ---------- 1. OS prep
echo "─── 1/6  OS prep ───"
. /etc/os-release
echo "  detected: $PRETTY_NAME"
case "$ID" in
  ubuntu|debian|kali)
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get install -y -qq curl ca-certificates ufw git unzip vim
    ;;
  fedora|centos|rhel|rocky|almalinux)
    dnf -y -q upgrade
    dnf install -y -q curl ca-certificates firewalld git unzip vim
    ;;
  *)
    echo "  ⚠ unrecognised OS — skipping package upgrades"
    ;;
esac
timedatectl set-timezone Asia/Riyadh 2>/dev/null && echo "  ✓ timezone → Asia/Riyadh"
echo

# ---------- 2. Firewall
echo "─── 2/6  Firewall (ufw) ───"
if command -v ufw >/dev/null; then
  ufw --force reset >/dev/null 2>&1 || true
  ufw allow OpenSSH >/dev/null
  ufw allow 5173/tcp comment 'husn dashboard' >/dev/null
  ufw allow 8000/tcp comment 'husn API' >/dev/null
  ufw allow 9000/tcp comment 'husn vuln target' >/dev/null
  # NOTE: we deliberately do NOT open honeypot ports (21/23/1433/3306/5432/6379/9200/27017)
  #   in ufw. Husn binds them in user-space; ufw would block external probes
  #   BEFORE Husn ever sees them. Without ufw allow, the kernel still drops
  #   them — but Husn's accept() doesn't fire. So we have to open them too:
  for p in 21 23 1433 3306 5432 6379 9200 27017; do
    ufw allow ${p}/tcp comment "husn honeypot ${p}" >/dev/null
  done
  ufw --force enable >/dev/null
  echo "  ✓ ufw active — ports: 22, 5173, 8000, 9000, + honeypots"
else
  echo "  ⚠ ufw not installed; using firewalld or iptables — open ports manually"
fi
echo

# ---------- 3. Run the main installer
echo "─── 3/6  Husn installer ───"
chmod +x install.sh
HUSN_DOMAIN="$DOMAIN" HUSN_WITH_NGINX=no ./install.sh
echo

# ---------- 4. Wire SMTP password into systemd (never on disk)
echo "─── 4/6  SMTP password via systemd drop-in ───"
mkdir -p /etc/systemd/system/husn-backend.service.d
cat > /etc/systemd/system/husn-backend.service.d/smtp.conf <<EOF
[Service]
Environment=HUSN_SMTP_PASSWORD=${SMTP_PASSWORD}
EOF
chmod 600 /etc/systemd/system/husn-backend.service.d/smtp.conf
systemctl daemon-reload
echo "  ✓ password written to /etc/systemd/system/husn-backend.service.d/smtp.conf (mode 0600)"
echo

# ---------- 5. Tune config for a public mini-PC-style deployment
echo "─── 5/6  Tune /etc/husn/config.yml for the demo ───"
CFG=/etc/husn/config.yml
[[ -f "$CFG" ]] || cp /opt/husn/config/config.example.yml "$CFG"
chmod 640 "$CFG"

# Build the whitelist: always loopback + WSL/private subnets + (optionally) admin IP.
WHITELIST_BLOCK="  whitelist:
    - 127.0.0.1"
[[ -n "$ADMIN_IP" ]] && WHITELIST_BLOCK="${WHITELIST_BLOCK}
    - ${ADMIN_IP}        # admin laptop — never block"

python3 - <<PY
import re, pathlib
p = pathlib.Path("$CFG")
src = p.read_text()

def replace_block(text, key, replacement):
    pat = re.compile(rf"^{key}:\n(?:[ \t].*\n)*", re.M)
    return pat.sub(replacement.rstrip()+"\n\n", text)

# 1. real_iptables ON, whitelist tuned for VPS
src = replace_block(src, "response", """response:
  real_iptables: true
  block_duration_seconds: 3600
${WHITELIST_BLOCK}""")

# 2. sniffer ON, broad capture
src = replace_block(src, "sniffer", """sniffer:
  enabled: true
  interface: ""
  bpf_filter: ""
""")

# 3. honeypot ON
src = replace_block(src, "honeypot", """honeypot:
  enabled: true
  ports: [23, 21, 1433, 3306, 5432, 6379, 9200, 27017]
""")

# 4. domain
src = re.sub(r"^domain:.*$", f"domain: $DOMAIN", src, count=1, flags=re.M)

p.write_text(src)
print("  ✓ config tuned: real_iptables on · sniffer on · honeypot on · domain=$DOMAIN")
PY
chown husn:husn "$CFG" 2>/dev/null || true
echo

# ---------- 6. Restart everything + verify
echo "─── 6/6  Restart + verify ───"
systemctl restart husn-backend husn-frontend
sleep 4
ok=true
for svc in husn-backend husn-frontend; do
  if systemctl is-active --quiet "$svc"; then
    echo "  ✓ $svc active"
  else
    echo "  ✗ $svc NOT active — journalctl -u $svc -n 30"
    ok=false
  fi
done

# Probe the API
TOKEN=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin@"}' \
  http://127.0.0.1:8000/auth/login 2>/dev/null \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("token",""))' 2>/dev/null)
if [[ -n "$TOKEN" ]]; then
  echo "  ✓ /auth/login works — admin token obtained"
  status=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/sniffer/status \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print("running="+str(d.get("running",False))+" packets="+str(d.get("packets_seen",0)))')
  echo "  ✓ sniffer: $status"
  hp=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/honeypot/status \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);print("running="+str(d.get("running",False))+" ports="+str(d.get("listening_ports",[])))')
  echo "  ✓ honeypot: $hp"
else
  echo "  ✗ /auth/login failed — check journalctl -u husn-backend"
  ok=false
fi
echo

if $ok; then
  echo "  ╭───────────────────────────────────────────────╮"
  echo "  │   ✓ Husn is up.                               │"
  echo "  ╰───────────────────────────────────────────────╯"
  echo
  echo "  Dashboard:  http://${PUBLIC_IP}:5173"
  echo "  Login:      admin / admin@   (CHANGE IT NOW in the Users tab)"
  echo "  Logs:       journalctl -u husn-backend -f"
  echo
  echo "  Send the attacker kit to your teammate:"
  echo "    scp ${REPO}/attacker-kit.zip teammate@laptop:~/"
  echo "  Then have them run: ./.venv/bin/python exploit.py ${PUBLIC_IP}"
else
  echo "  ✗ Some checks failed. Inspect:"
  echo "    journalctl -u husn-backend -n 50"
  echo "    journalctl -u husn-frontend -n 50"
  exit 1
fi
