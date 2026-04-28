#!/usr/bin/env bash
# Husn — 3-pane tmux demo launcher.
#
# Spins up everything you need on one screen for the contest:
#
#   ┌───────────────────────────────┬─────────────────────┐
#   │                               │                     │
#   │   HUSN CLI                    │   backend log tail  │
#   │   (banner + interactive       │   (real-time API    │
#   │    husn> prompt)              │    + sniffer +      │
#   │                               │    honeypot events) │
#   │                               │                     │
#   ├───────────────────────────────┴─────────────────────┤
#   │                                                     │
#   │   ATTACKER shell  (exploit command pre-typed)       │
#   │                                                     │
#   └─────────────────────────────────────────────────────┘
#
# Hot-keys (all use the tmux prefix `Ctrl+b`):
#   Ctrl+b → ↑/↓/←/→     move focus between panes
#   Ctrl+b z              maximise / restore the focused pane
#   Ctrl+b d              detach (session keeps running)
#   Ctrl+b &              kill the whole session
#
# Re-attach later:  tmux attach -t husn-demo
# Force-restart:    ./demo.sh --restart
set -euo pipefail

SESSION="husn-demo"
ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET="${HUSN_TARGET:-127.0.0.1}"
PASSWORD="${HUSN_SMTP_PASSWORD:-Husn\$0542306151}"

# ---------- preflight
if ! command -v tmux >/dev/null 2>&1; then
  echo "✗ tmux not installed."
  echo "  sudo apt install -y tmux    # debian/ubuntu/kali"
  echo "  sudo dnf install -y tmux    # fedora/rhel"
  exit 1
fi

if [[ "${1:-}" == "--restart" ]]; then
  tmux kill-session -t "$SESSION" 2>/dev/null || true
fi

# If session already exists, just attach.
if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "↪ attaching to existing demo session ($SESSION)"
  exec tmux attach -t "$SESSION"
fi

mkdir -p "$ROOT/logs"
: > "$ROOT/logs/backend.log"   # truncate so the tail starts clean

# ---------- create the session (detached)
tmux new-session -d -s "$SESSION" -c "$ROOT" -x 220 -y 50
tmux rename-window -t "$SESSION:0" husn

# 3 panes: left big (HUSN CLI), top-right (log tail), bottom-right (attacker)
tmux split-window -h -t "$SESSION:0.0"           -c "$ROOT"   # right half
tmux split-window -v -t "$SESSION:0.1"           -c "$ROOT"   # split right into top/bottom
tmux select-layout -t "$SESSION:0" main-vertical
tmux resize-pane   -t "$SESSION:0.0" -x 130                   # widen left for the HUSN CLI

# Pane titles — visible in the status bar of each pane
tmux set -t "$SESSION" -g pane-border-status top
tmux set -t "$SESSION" -g pane-border-format "  #{?pane_active,#[bold #[fg=green],#[fg=colour244]}#T#[default]  "
tmux select-pane -t "$SESSION:0.0" -T " HUSN  defender "
tmux select-pane -t "$SESSION:0.1" -T " backend log "
tmux select-pane -t "$SESSION:0.2" -T " ATTACKER  shell "

# Status line — clean + branded
tmux set -t "$SESSION" -g status-style "bg=colour234,fg=colour250"
tmux set -t "$SESSION" -g status-left  " #[bold]HUSN demo#[default]  session #S "
tmux set -t "$SESSION" -g status-right " target: #[bold]$TARGET#[default]  ·  Ctrl+b d to detach "
tmux set -t "$SESSION" -g status-left-length 60
tmux set -t "$SESSION" -g status-right-length 60

# ---------- pane 0: launch Husn (full stack + CLI in foreground)
tmux send-keys -t "$SESSION:0.0" \
  "clear && export HUSN_SMTP_PASSWORD='$PASSWORD' && ./backend/venv/bin/python run.py both" Enter

# ---------- pane 1: tail backend log (will appear once Husn starts writing)
tmux send-keys -t "$SESSION:0.1" \
  "clear && echo 'waiting for backend log...' && until [[ -s logs/backend.log ]]; do sleep 1; done && tail -F logs/backend.log" Enter

# ---------- pane 2: attacker shell — pre-type the exploit, do NOT auto-run
#   The user just hits Enter when judges are watching the dashboard.
tmux send-keys -t "$SESSION:0.2" \
  "clear && echo '┌────────────────────────────────────────────────────────────┐'
echo '│  ATTACKER terminal — when judges are watching, press Enter │'
echo '│                                                            │'
echo '│  Dashboard:  http://localhost:5173   (admin / admin@)      │'
echo '│  Topology:   the moment Enter is pressed, watch your IP    │'
echo '│              appear as a red node                          │'
echo '└────────────────────────────────────────────────────────────┘'
echo
" Enter
tmux send-keys -t "$SESSION:0.2" \
  "./backend/venv/bin/python exploit.py $TARGET"
# (no Enter — command is queued at the prompt for the user to launch)

# ---------- focus the attacker pane on attach so user can press Enter immediately
tmux select-pane -t "$SESSION:0.2"

echo "✓ demo session ready — attaching..."
sleep 0.5
exec tmux attach -t "$SESSION"
