#!/usr/bin/env bash
# Husn attacker kit — one-shot setup for the teammate's laptop.
#
# This puts no agents, no daemons, no auto-start anything on the laptop.
# It just installs the single Python dep `requests` so the exploit can run.
#
# Usage:
#   ./setup.sh                  # install deps
#   ./setup.sh <husn-ip>        # install deps + dry-run reachability check
set -euo pipefail

cd "$(dirname "$0")"

echo "─── Husn attacker-kit setup ───"

# 1. Make sure Python 3 is present.
if ! command -v python3 >/dev/null 2>&1; then
  echo "✗ Python 3 not installed."
  echo "  macOS:    brew install python"
  echo "  Linux:    sudo apt install -y python3 python3-pip   (or your distro equivalent)"
  echo "  Windows:  https://www.python.org/downloads/"
  exit 1
fi
echo "✓ python3 → $(python3 --version)"

# 2. Install requests in a tiny local venv so we don't pollute the laptop.
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
./.venv/bin/pip install -q --upgrade pip
./.venv/bin/pip install -q -r requirements.txt
echo "✓ requests installed in ./.venv"

# 3. Optional reachability check.
if [[ "${1:-}" != "" ]]; then
  TARGET="$1"
  echo
  echo "─── Reachability check against $TARGET ───"
  if ./.venv/bin/python -c "
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(('$TARGET', 9000))
    print('✓ port 9000 reachable — exploit will work')
except Exception as e:
    print(f'✗ cannot reach $TARGET:9000 — {e}')
    sys.exit(1)
"; then
    echo
    echo "Ready. To run the exploit:"
    echo "  ./.venv/bin/python exploit.py $TARGET"
  else
    exit 1
  fi
else
  echo
  echo "Ready. When the contest starts:"
  echo "  ./.venv/bin/python exploit.py <husn-ip>"
  echo
  echo "Tip: pre-flight a reachability check with"
  echo "  ./setup.sh <husn-ip>"
fi
