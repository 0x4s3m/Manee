# Husn (حصن) — System Walkthrough

A complete, code-level explanation of how the CLI and the dashboard work,
how the components fit together, and what actually happens when you click
each button. Written for the DefensThon 2026 demo team.

## Contents
1. [The mental model](#1-the-mental-model)
2. [The CLI — what every command actually does](#2-the-cli--what-every-command-actually-does)
3. [The Dashboard — every tab, every button](#3-the-dashboard--every-tab-every-button)
4. [The full attack → block → email trace](#4-the-full-attack--block--email-trace)
5. [The 5-minute updater loop](#5-the-5-minute-updater-loop)
6. [The contest-day mental checklist](#6-the-contest-day-mental-checklist)

---

## 1. The mental model

Husn has three live processes and one passive store:

```
                     ┌────────────────────────┐
                     │  /etc/husn/config.yml  │ (or config/config.example.yml)
                     └────────────┬───────────┘
                                  │ loaded once at startup
                                  ▼
   ┌─────────┐  HTTP  ┌──────────────────────┐  imports   ┌──────────────┐
   │ React   │◀──────▶│  FastAPI backend     │───────────▶│  HusnAI      │
   │ :5173   │        │  :8000               │            │  Responder   │
   └─────────┘        │                      │            │  Scheduler   │
                      └─────┬───────┬────────┘            └──────────────┘
                            │       │
                            │       └─────▶  SMTP  ─────▶  inbox
                            │
                            └─────▶ shells out to: iptables, git, (nmap)

   ┌────────────────┐
   │ Husn CLI       │  imports the SAME modules — no HTTP, no backend needed.
   │ (Rich/Typer)   │  Runs in your terminal.
   └────────────────┘
```

The CLI and the dashboard are **two different front-ends to the same Python
code**. The CLI calls Python functions directly (`hardware.snapshot()`,
`responder.block_ip()`). The dashboard calls those same functions through
HTTP endpoints (`/system/hardware`, `/blocked`). That's why everything stays
in sync.

---

## 2. The CLI — what every command actually does

Launch: `python run.py cli` (or it boots automatically inside `python run.py both`).

### Startup
1. **Boot sequence** — animated spinner with three phases ("Initializing HUSN
   Core" → "Loading AI Modules" → "Probing host telemetry" → "Establishing
   secure SIEM tunnel"). Pure visual; no real work.
2. **Banner** — the green ASCII shield + a status line showing where the
   config was loaded from, whether SMTP is on, and whether iptables is in
   real or simulated mode.
3. **Auto-runs `sysinfo`** so judges immediately see your real hardware.
4. **Help panel** with the command list, then drops you into the `husn >`
   prompt with tab-completion.

### Commands

| Command | What it actually does |
|---|---|
| `sysinfo` | Calls `hardware.snapshot()` (psutil + platform). Renders three panels: **HOST OVERVIEW** (hostname/OS/uptime/CPU/RAM/swap), **DISKS** (per-mount with %-used colour-coded), **INTERFACES** (per-NIC IPv4/MAC/up-state/speed). |
| `ports` | Calls `network.listening_ports()` → `psutil.net_connections(kind='inet')` filtered to LISTEN state. Shows port, protocol, bind address, service name (looked up from a 70-entry IANA table + `socket.getservbyport`), PID, and owning process. |
| `services` | Same data as `ports` but **grouped by process** — one row per service binary with all its ports collapsed into a single cell. Useful for "what's actually serving on this box?" at a glance. |
| `procs` / `procs --suspicious` | Calls `processes.list_processes(40)` (or `.suspicious_only()`). Each process gets run through `_classify()`: known-bad-name list (kdevtmpfsi, kinsing, xmrig, …), executable path under `/tmp` or `/dev/shm`, untrusted binary path *combined with* an active network connection, or cryptominer flags in the cmdline (`--donate-level`, `stratum+tcp`, etc.). Sorted suspicious-first, then by CPU%. |
| `scan <target>` | Calls `scanner.scan(target)`. First tries `nmap -sV -Pn -T4 --open` (since you're on Kali, this always wins → service-version detection). Falls back to a 64-thread TCP-connect probe across ~40 well-known ports if nmap isn't on PATH. Returns engine name + duration so you can prove it's real. |
| `scan` (no arg) | Falls back to the legacy "Live Packet Inspection" — random `PASS/BLOCK/INSPECT` rows refreshed 4×/sec for 4 seconds. Pure demo flair. At iteration 10 it deliberately fires `responder.block_ip("104.21.x.x", attack_type="Infiltration", severity="High", confidence=0.94)` so you can show the block-and-email flow without setting up a real attack. |
| `simulate` | Prompts for an attack type, then shows a two-stage progress bar ("Crafting packets" → "Injected payloads"). The CLI version is **visual only** — for the real AI hit, use the dashboard's Simulation tab (which calls `/simulate` and drives the AI through `ai.predict(..., source_ips=...)`). |
| `status` | Holistic: AI online, network monitor active, SMTP enabled/disabled, iptables real/simulated (in red if real), count of currently blocked IPs, count of recipients. |
| `blocked` | Calls `responder.list_blocked()` — the in-memory dict the response module maintains. Shows IP, attack type, severity, confidence, when. |
| `check` | Calls `updater.check()` → `git fetch origin <branch>` + `git rev-list --left-right --count HEAD...origin/<branch>`. Reports behind/ahead counts and current/remote commit SHAs. Doesn't mutate anything. |
| `update` | Calls `updater.check()` first; if behind > 0, asks confirmation, then `git pull --ff-only`. If `requirements.txt` changed (byte comparison), runs `pip install -r requirements.txt`. Refuses to pull onto a dirty tree. |
| `report-test` | Calls `report.send_test_email()` — synthesises a fake `Incident(source_ip="203.0.113.42", attack_type="Test Alert", ...)`, persists Markdown+HTML+JSON, and sends the HTML version through the configured SMTP. Same path as the Defense-tab button. |
| `dashboard` | Just prints the URL. |
| `clear` | Re-shows the banner. |
| `exit` | Bye. |

### What's running in the background
`updater.start_scheduler()` is **only invoked from FastAPI's lifespan** — so
the 5-minute auto-check is part of the *backend*, not the CLI. The CLI is
purely interactive.

---

## 3. The Dashboard — every tab, every button

Launch: `python run.py both` (boots backend on :8000 and dashboard on :5173).
Open http://localhost:5173.

### What's polling
Two loops live in `App.tsx`:

| Loop | Period | Endpoints | Why |
|---|---|---|---|
| **Fast** | 2 seconds | `/status`, `/monitor`, `/logs` | Cheap, drives the live counters and SIEM stream |
| **Slow** | 5 seconds | `/system/hardware`, `/system/ports`, `/system/processes`, `/blocked`, `/recipients`, `/updates/status` | Heavier endpoints (psutil walks, etc.) |

So when you open the dashboard, the Host/Network/Defense/Updates tabs are
already populated within 5 seconds without you clicking anything.

### Always-visible chrome

- **Sidebar** (left in EN, right in AR, auto-switches): 9 tab links. Two have
  live indicators:
  - **Defense** gets a red badge with the count of currently blocked IPs.
  - **Updates** gets a yellow pulsing dot when `last_check.available` is true
    (i.e. you're behind origin).
- **Lang toggle** at the bottom of the sidebar — flips `lang` state, which
  flips `dir="rtl"` on the root element and rewrites every label from
  `i18n.ts`.
- **CPU% bar** — driven by `hwSnapshot.cpu.usage_percent` from the slow-poll,
  updates smoothly because of CSS transition.
- **National Defense toggle** — POSTs `/toggle-defense`. Backend flips
  `ai.defense_mode` between "Standard" and "National". Inside `ai.predict()`,
  National mode randomly turns ~30% of normal anomaly scores into anomalies,
  and `/monitor` returns a higher malicious-traffic floor. The button itself
  starts pulsing red.
- **Top header** — the target IP input + "Run Network Scan" button (these
  drive the existing `/scan` flow on the AI side, *not* the system scanner).
  Right side shows the real hostname pulled from `/system/hardware`.
- **Right log panel** — last 30 entries from the backend's in-memory log list.
  Lines containing `BLOCK`, `ACTIVE`, `[+]` get coloured cyan; `ERR`/`!` get
  coloured red. Auto-scrolls to bottom.
- **Active Shield card** below the log panel — shows "REAL BLOCKING" or
  "Simulated" depending on `systemStatus.real_iptables`.

### Tab 1 — Dashboard

What you see:
1. **Three novelty cards** at the top — Self-Learning rate, Knowledge Base
   Size, Threat Level.
   - These come from `/status` → `ai.learning_rate` (decays 1% per `predict()`
     call) and `ai.knowledge_base_size` (grows by `len(X)` per call). They're
     **simulated** (not a real online-learning loop) but they move when you
     fire attacks, which is what judges are looking at.
2. **Real-time line chart** (Recharts, 15-point sliding window) — green =
   incoming, cyan = outgoing, red = malicious. Source: `/monitor` returning
   `random.randint(...)` ranges. The malicious floor jumps when you toggle
   National Defense.
3. **4 quick-stats row** — CPU %, Memory %, Uptime, Blocked IPs (turns red
   if > 0). All from real data via slow-poll.
4. **SIEM Intelligence Feed** — the result rows from the last `/scan` call.
   Empty state shows a skull + "Awaiting Target Acquisition".

### Tab 2 — Host

Three big-metric cards (CPU, Memory, Uptime) with progress bars + sub-text
(cores, used/total GB, OS string).

Two side-by-side cards:
- **Disks** — table with mount, FS, total/used GB, %-used (colour-coded
  green<75%<yellow<90%<red).
- **Interfaces** — table with iface name, IPv4, MAC, up-status (green dot or
  grey X), speed.

A wide **Operating System** card showing hostname, FQDN, OS+release, kernel
version, Python version, machine arch.

Everything is live from `psutil` via `/system/hardware`.

### Tab 3 — Network

Two stacked cards:
- **Listening Ports (N)** — every LISTEN socket on your box: port, protocol,
  bind address, service (e.g. "HTTP", "SSH"), PID, process name.
- **Processes (N)** — top 40 by CPU%, with a toggle button **"Suspicious only
  ⇄ Show all"** in the card header. When in suspicious-only mode and there
  are zero, you see a green "✓ No suspicious processes detected" message.
  When a process is flagged, the rightmost column shows `⚠ <reason>` in red.

This is the page judges will linger on — these are real processes from your
real machine, not mockups.

### Tab 4 — Detection (recon)

Mostly a landing page that says "use the search bar above". When you type a
target IP and hit "Run Network Scan", `startScan()` POSTs `/scan` with
`{target}`, and the backend's `run_ai_scan()` samples 5 rows of the training
data and runs them through the AI. The result rows render here AND in the
Dashboard's SIEM feed.

### Tab 5 — Simulation (exploits)

Four big buttons:
- **DDoS Attack** → POSTs `/simulate` with `attack_type: "DDoS"`
- **Port Scan** → `attack_type: "Port Scan"`
- **SSH Brute Force** → `attack_type: "Brute Force"`
- **RCE Exploit** → `attack_type: "RCE Exploit"` (highlighted in red — this
  is the climax)

What happens server-side when you click any of these:
1. `trigger_simulation()` runs the matching `AttackSimulator` method —
   Scapy crafts and sends real packets (or warns "Scapy unavailable"
   gracefully on WSL2 without caps).
2. Then it loads sample rows from the training data matching the attack
   label (e.g. 3 rows where `label == "DDoS"`) and calls `ai.predict(matching,
   source_ips=[target_ip] * 3)` — passing whatever was in the target box on
   the dashboard.
3. Inside `predict()`, the AI flags those rows as anomalies + non-BENIGN
   labels, which triggers `responder.block_ip(target_ip, attack_type,
   severity, confidence)`.
4. **From there, the chain in §4 below kicks in.**

The red callout panel at the bottom of this tab explains the RCE flow to
judges.

### Tab 6 — Explainable AI (XAI)

Click **"RUN SHAP ENGINE"** → GET `/explain` returns the XGBoost classifier's
`feature_importances_` array as a sorted list. Recharts renders it as a
horizontal bar chart with red bars for positive (raised threat probability)
and cyan bars for negative (legitimate signal). The right column has an
interpretation legend.

This is the panel that justifies the "Explainable AI" claim — judges can ask
"why did you block that?" and you can point at the chart.

### Tab 7 — Defense

Two cards:

**Blocked IPs (N)** — table from `/blocked` showing IP, attack type, severity,
confidence %, when, and an **UNBLOCK** button per row. Clicking it POSTs
`/blocked/{ip}/unblock` which calls `responder.unblock_ip()` (real iptables
`-D` if in real mode, otherwise just removes from the registry).

**Email Recipients** — list from `/recipients`, plus a status pill (green
"ENABLED" or yellow "SMTP OFF" with the fix-it hint), plus an inline form to
add/remove recipients (POST/DELETE `/recipients`). Above all of it: the
**Send Test Email** button (top right of the tab). That POSTs `/test-alert`
→ `report.send_test_email()` → the same code path you just verified
end-to-end with Hostinger.

### Tab 8 — Updates

Header buttons: **Check Now** and **Apply Update** (the latter is greyed out
until `last_check.available` becomes true).

**Status card** with 8 fields (last checked, repo, branch, auto-apply, behind,
ahead, HEAD, origin) and a coloured banner showing the result message.

**History card** with the last 15 scheduler entries — each is one row with a
green check or red X, timestamp, action ("check" / "apply"), and the result
message. This is how you prove to judges that the auto-update channel is
real and running every 5 minutes.

### Tab 9 — Payloads

Three reference cards (SQL injection, XSS, RCE). Pure documentation/decoration
— no API calls.

---

## 4. The full attack → block → email trace

This is the trace you should know cold for the demo. When a judge clicks
**RCE Exploit** on the dashboard with `target = 203.0.113.5`:

1. **Browser** — `triggerSim('RCE Exploit')` → `axios.post('/simulate',
   {target_ip: '203.0.113.5', attack_type: 'RCE Exploit'})`.
2. **FastAPI** (`main.trigger_simulation`):
   1. `AttackSimulator('203.0.113.5').rce_exploit_simulation()` — Scapy emits
      15 large-payload TCP-PA packets with random source ports.
   2. Loads 3 training rows where `label == "Infiltration"`, runs
      `ai.predict(rows, source_ips=['203.0.113.5','203.0.113.5','203.0.113.5'])`.
3. **HusnAI.predict**:
   1. `IsolationForest.predict()` — `-1` for each row (anomalies).
   2. National-Defense amplification (no-op if Standard).
   3. `XGBClassifier.predict_proba()` → top class is `Infiltration`,
      confidence ~0.94.
   4. For each row, since anomaly + label != BENIGN: `severity = "High"`,
      calls `responder.block_ip("203.0.113.5", attack_type="Infiltration",
      severity="High", confidence=0.94)`.
4. **DefenseResponse.block_ip**:
   1. **Whitelist check** — `203.0.113.5` not in `127.0.0.1` list, proceed.
   2. **Action** — if `response.real_iptables: true`, runs
      `subprocess.run(["iptables", "-A", "INPUT", "-s", "203.0.113.5", "-j",
      "DROP"])`. Otherwise just logs.
   3. Adds `{ip, blocked_at, attack_type, severity, confidence}` to
      `_blocked` dict.
   4. Schedules a `threading.Timer` to auto-unblock after
      `block_duration_seconds` (default 3600).
   5. Calls `report.emit(Incident(...), feature_importance=ai.feature_importance())`.
5. **report.emit**:
   1. Saves Markdown + HTML + JSON to
      `/var/log/husn/reports/<timestamp>_203.0.113.5_Infiltration.{md,html,json}`.
   2. Renders the SHAP feature-importance chart as a PNG using headless
      matplotlib (`MPLCONFIGDIR=/tmp/matplotlib`, `Agg` backend).
   3. **Throttle check** — has any email about `203.0.113.5` been sent in
      the last 60s? If yes, return early (report still on disk).
   4. Otherwise: `mailer.send(subject, html, text, inline_images={"shap_chart":
      png}, attachments={...md})`.
6. **mailer.send**:
   1. Builds `EmailMessage` with `Subject`, `From`, `To`, `Date`, `Message-ID`.
   2. Sets plain-text body, then adds the HTML alternative.
   3. Attaches the SHAP PNG with `Content-ID: <shap_chart>` so the HTML's
      `<img src="cid:shap_chart">` resolves inline.
   4. Attaches the Markdown report as a downloadable file.
   5. Connects via `smtplib.SMTP_SSL(host, 465)` (Hostinger path) → `login()`
      → `send_message()`.
   6. Returns `SendResult(ok=True, detail="delivered", recipients=[...])`.
7. **Frontend** — within 5 seconds, the slow-poll's next tick hits `/blocked`
   and `/logs`. The Defense tab updates with the new entry; the right-panel
   log shows `ACTIVE DEFENSE: Blocking malicious IP 203.0.113.5...`; the
   Defense tab badge appears in the sidebar.
8. **Inbox** — within ~3 seconds of the click, an HTML email lands at
   `t.m.j.a.r3@gmail.com` with the dark-themed incident card and the SHAP
   chart inline.

That's the entire chain. Every step is real except the AI training data is
synthetic and the iptables rule (in dev mode only) is logged instead of
executed.

---

## 5. The 5-minute updater loop

Independent of everything above. When the FastAPI app starts, `lifespan`
calls `updater.start_scheduler()`, which:
1. Reads `updater.interval_minutes` (default 5) and `updater.auto_apply`
   (default false).
2. Creates an APScheduler `BackgroundScheduler(daemon=True, timezone="UTC")`.
3. Adds a job with `interval=5 min` calling `_tick()`.
4. `_tick()` runs `check()` (git fetch + rev-list); if `auto_apply` is true
   and updates are available, also runs `apply()` (git pull + pip install if
   reqs changed).
5. Every result is appended to a 50-entry deque (`_history`) which the
   Updates tab and CLI both read.

The scheduler is **idempotent** — calling `start_scheduler()` twice doesn't
double-schedule.

---

## 6. The contest-day mental checklist

When you're standing in front of judges, here's what's actually happening
behind each click:

| Click | Backend code path | Visible result |
|---|---|---|
| Open dashboard | Fast-poll starts; slow-poll fires immediately | All tabs populated within 5s |
| Toggle EN/AR | Pure frontend; rewrites every label from `i18n.ts` | Layout flips RTL ↔ LTR |
| Toggle National Defense | POST `/toggle-defense` → `ai.defense_mode = "National"` | Sidebar button pulses red, malicious traffic floor jumps |
| Click RCE Exploit | The 8-step chain in §4 | Block appears, email lands, SHAP chart explains why |
| Click Send Test Email | POST `/test-alert` → `report.send_test_email()` → fake incident | Test email lands in 3s |
| Click Run SHAP Engine | GET `/explain` → `ai.feature_importance()` | Bar chart renders |
| Click Check Now (Updates) | POST `/updates/check` → `git fetch` + counts | Status banner updates |

Everything else is either a poll result or pure frontend.
