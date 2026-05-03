#!/usr/bin/env bash
# tab-recommender.sh — read frontend/src/App.tsx, list every dashboard tab
# the user can navigate to, measure how much real estate each one takes,
# and surface candidates for deletion based on:
#
#   • how rarely it would be used in a 4-minute live demo
#   • how much overlap it has with other tabs (telemetry duplication)
#   • whether it adds actual value vs. eye candy
#
# Run from the husn project root:   bash tab-recommender.sh
#
# Output is opinionated — the script makes recommendations, but you decide.

set -euo pipefail

APP="frontend/src/App.tsx"
[[ -f "$APP" ]] || { echo "✗ Run from the husn project root (where frontend/ lives)." >&2; exit 1; }

# ─────────────────── 1. Discover every tab ───────────────────
# Tabs are detected by the activeTab === '<key>' pattern that gates each tab
# block. We pull a unique sorted list.
mapfile -t KEYS < <(grep -oE "activeTab === '[a-z\-]+'" "$APP" \
                    | sed -E "s/activeTab === '//; s/'$//" \
                    | sort -u)

# ─────────────────── 2. Verdict matrix ───────────────────
# (key | demo-friendly label | role | recommendation | reason)
# The recommendation column is one of:
#   KEEP     — core to the demo narrative, judges WILL look here
#   KEEP*    — useful but not on the critical path
#   FOLD     — could be merged into another tab to slim the sidebar
#   DROP     — weak demo value, redundant, or noise
declare -A LABEL REC REASON

LABEL[dashboard]="Dashboard"
REC[dashboard]="KEEP"
REASON[dashboard]="Hero KPIs land first. Most-used tab in the demo."

LABEL[kill-chain]="Kill Chain"
REC[kill-chain]="KEEP"
REASON[kill-chain]="Star feature. Visual proof the attacker was contained at stage 4. Pitch references this directly."

LABEL[host]="Host"
REC[host]="KEEP*"
REASON[host]="Solid 'we know your box' tab — CPU/RAM/disks. Useful but not pitched."

LABEL[network]="Network & Processes"
REC[network]="KEEP*"
REASON[network]="Suspicious-process flagging is a nice judge-impression moment if asked."

LABEL[connections]="Connections"
REC[connections]="FOLD"
REASON[connections]="Largely redundant with Topology — same data viewed differently. Fold into Topology."

LABEL[topology]="Topology"
REC[topology]="KEEP*"
REASON[topology]="Visual graph reads well in a screenshot, but the live force-graph can lag on weak machines. Have a fallback."

LABEL[recon]="Threat Detection"
REC[recon]="DROP"
REASON[recon]="The 'scan' button overlaps with the header search. AI Inspector + Defense already cover what an analyst needs."

LABEL[xai]="Explainable AI"
REC[xai]="FOLD"
REASON[xai]="The SHAP chart is cooler when shown inside an actual incident (AI Inspector's expanded row, or the email). Standalone it's abstract. Fold into AI Inspector."

LABEL[ai-inspect]="AI Inspector"
REC[ai-inspect]="KEEP"
REASON[ai-inspect]="Where the demo lives — payloads + features + signature pills. Critical."

LABEL[defense]="Active Defense"
REC[defense]="KEEP"
REASON[defense]="Lists currently blocked IPs + whitelist controls. Judges will ask to see this."

LABEL[honeypot]="Honeypot"
REC[honeypot]="KEEP*"
REASON[honeypot]="Easy 'wow' if a probe hits it during the demo, but mostly empty. Worth ~30s mention only."

LABEL[chat]="SOC Chat"
REC[chat]="KEEP"
REASON[chat]="LLM live demo — type a question, get an answer. Pitch references this."

LABEL[reports]="Reports"
REC[reports]="KEEP*"
REASON[reports]="Auto-summary emails. Shown once in the pitch, otherwise an admin tab."

LABEL[updates]="Updates"
REC[updates]="DROP"
REASON[updates]="Git-fetch update checker — internal-ops only. No judge-value. Hide behind /admin URL."

LABEL[terminal]="Terminal"
REC[terminal]="KEEP*"
REASON[terminal]="In-UI CLI shows technical depth. Pre-load 'status' for the pitch."

LABEL[users]="Users"
REC[users]="KEEP*"
REASON[users]="Admin-only. Showcases the secure user-mgmt panel. Quick mention only."

LABEL[autopatch]="Auto Patch"
REC[autopatch]="KEEP"
REASON[autopatch]="Star feature #2. The 'we patch our own code' moment. Critical to the pitch."

# ─────────────────── 3. Count tab content size in lines ───────────────────
# Rough heuristic: lines between the activeTab gate and the next gate (or
# the close of the AnimatePresence block). Helps prioritise deletions by
# code-mass freed.
get_size() {
  local key="$1"
  awk -v key="$key" '
    $0 ~ "activeTab === \047" key "\047" { in_block = 1; depth = 0; next }
    in_block { lines++ }
    in_block && /<Tab k=/ { depth++ }
    in_block && /<\/Tab>/ { depth--; if (depth == 0) { print lines; exit } }
  ' "$APP"
}

# ─────────────────── 4. Render the report ───────────────────
RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'; CYN=$'\033[0;36m'; RST=$'\033[0m'
color_for() {
  case "$1" in
    DROP)   echo -n "$RED" ;;
    FOLD)   echo -n "$YEL" ;;
    KEEP*)  echo -n "$GRN" ;;
    KEEP)   echo -n "$CYN" ;;
  esac
}

echo
echo "╭──────────────────────────────────────────────────────────────────╮"
echo "│  Manee Dashboard — Tab Recommender                               │"
echo "│  Reads $APP and rates each tab        │"
echo "╰──────────────────────────────────────────────────────────────────╯"
echo
printf "%-14s  %-22s  %-7s  %-6s  %s\n" "KEY" "LABEL" "VERDICT" "LINES" "REASON"
printf "%-14s  %-22s  %-7s  %-6s  %s\n" "─────────────" "─────────────────────" "───────" "──────" "──────────────────────────"

DROP_COUNT=0; FOLD_COUNT=0; KEEP_COUNT=0; UNKNOWN=0
TOTAL_DROP_LINES=0

for key in "${KEYS[@]}"; do
  size=$(get_size "$key")
  size=${size:-0}
  label="${LABEL[$key]:-(unmapped)}"
  rec="${REC[$key]:-?}"
  reason="${REASON[$key]:-No verdict — review manually.}"
  c=$(color_for "$rec")

  printf "${c}%-14s  %-22s  %-7s  %-6s  %s${RST}\n" "$key" "$label" "$rec" "$size" "$reason"

  case "$rec" in
    DROP)  DROP_COUNT=$((DROP_COUNT+1)); TOTAL_DROP_LINES=$((TOTAL_DROP_LINES+size)) ;;
    FOLD)  FOLD_COUNT=$((FOLD_COUNT+1)) ;;
    KEEP*) KEEP_COUNT=$((KEEP_COUNT+1)) ;;
    *)     UNKNOWN=$((UNKNOWN+1)) ;;
  esac
done

echo
echo "─── Summary ───────────────────────────────────────────────────────"
printf "  KEEP   : %2d tabs (essential to the demo or admin work)\n" "$KEEP_COUNT"
printf "  FOLD   : %2d tabs (worth merging into another tab)\n" "$FOLD_COUNT"
printf "  DROP   : %2d tabs (weak demo value — candidates for removal)\n" "$DROP_COUNT"
[[ $UNKNOWN -gt 0 ]] && printf "  ?      : %2d tabs (no verdict in script — review manually)\n" "$UNKNOWN"
echo
printf "  Removing the DROP tabs would delete ~%d lines of App.tsx\n" "$TOTAL_DROP_LINES"
echo

# ─────────────────── 5. Concrete recommendations for the pitch ───────────────────
cat <<'EOF'
─── Action plan if you have 10 minutes before judges ──────────────────
  1. DROP `recon` (Threat Detection)  — duplicates AI Inspector + the
     header search. Removing it tightens the Defense section.

  2. DROP `updates`                   — internal git-pull tool. Move it
     to a hidden URL or just remove.

  3. FOLD `connections` → `topology`  — same data, two views. Topology
     wins visually.

  4. FOLD `xai` → `ai-inspect`        — SHAP charts are more compelling
     when shown inside the row that triggered them. The AI Inspector's
     expanded row already has a "features" panel.

  After these four changes, the sidebar Defense section drops from 4
  items to 2 (AI Inspector, Active Defense, Honeypot only), and the
  whole sidebar feels less crowded for the demo. Code mass removed:
EOF
printf "  ~%d lines of App.tsx eliminated.\n\n" "$TOTAL_DROP_LINES"
echo "  Want me to make the deletions for you? Just say which tabs to drop."
echo
