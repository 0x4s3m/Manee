# Manee · منيع — Intelligent Cyber Defense System

<div align="center">
  <h3>Defense in depth, end to end. From packet to patch in 12 seconds.</h3>
  <p><b>DefensThon 2026 — Official Submission</b></p>
  <p><i>منيع — Arabic for <b>impregnable</b></i></p>
</div>

---

Manee is a deployable cyber-defense system that runs on any Linux box (or
macOS for development). It combines a hybrid AI engine, a payload-signature
scanner, real iptables blocking, an LLM-powered SOC analyst, and an
auto-patch advisor that proposes source-level fixes for vulnerabilities in
your own code. Same codebase runs as `python run.py both` on a laptop *and*
installs to `/opt/husn` with systemd units on a VPS.

The narrative the system sells:

> **Real attack → AI detection → SHAP explanation → real iptables block → email alert with inline SHAP chart → AI-suggested code patch**

---

## What's new in this release

| Feature | Why it matters |
|---|---|
| **🛡 Two-layer detection** | XGBoost+IsolationForest *plus* a 27-rule signature scanner (SQLi, XSS, log4shell, RCE, scanners, weak creds, LOLBins…). Either layer blocks. |
| **🎯 Kill Chain Visualizer** | Maps every detection onto the 7 Lockheed Martin stages. Live radar around your host node. |
| **🔍 AI Inspector** | Live feed of every flow the AI scored — payload preview, signature match, all 17 features per packet. |
| **💬 SOC Analyst chatbot** | DeepSeek LLM with live-state grounding. Bilingual EN/AR. |
| **🔧 Auto Patch** | Static analysis (13 rules) + LLM-assisted patches over your own source. Backup-protected, hash-audited, admin-approved. Single-issue or bulk fix. |
| **📧 Email-driven SOC** | Send `manee@your-domain` an email; get an LLM reply. Slash commands work — `/block`, `/whitelist`, `/investigate`, `/scan`, `/status`. Authorized-sender allowlist. |
| **📨 Hardened email template** | Severity-themed hero, signature pill, recommended actions, inlined SHAP chart, EN+AR explanation. Outlook-safe. |
| **🌐 Mobile-responsive UI** | Drawer sidebar on phone, slim icon column on tablet, full layout on desktop. |
| **🛟 Whole-project backups** | One-click tarball snapshots of the source tree, listed/downloadable from the dashboard. |
| **🎬 Cinematic topology** | d3-force graph with radar rings around the host, animated red particles on attacker links, click-to-inspect side drawer. |

---

## Two ways to run it

### 1. Local (Kali / Ubuntu / WSL2 / macOS / Any linux)
```bash
git clone https://github.com/0x4s3m/manee.git && cd manee
sudo bash install-manee.sh        # auto-detects OS, installs everything
python run.py both                # OR start manually
```

Open:
- Dashboard: http://localhost:5173 — login `admin / admin@`
- API:        http://localhost:8000/docs
- Vuln target: http://localhost:9000

### 2. Production server install (universal)
```bash
sudo bash install-manee.sh
```

The installer auto-detects your OS family (**Debian / RHEL / Arch / Alpine / macOS**) and:
- Installs Python 3.9+, Node.js 20, libpcap, libcap, iptables, build tools
- Creates the `husn` system user
- Builds the Python venv + bootstraps the AI models
- Builds the React production bundle
- Grants `cap_net_raw,cap_net_admin` to the venv Python
- Registers three systemd units (or falls back to a bare init script)
- Drops a config template at `/etc/husn/config.yml`
- Optional nginx + Let's Encrypt setup with `MANEE_DOMAIN=foo.bar MANEE_WITH_NGINX=yes`

After install:
```bash
sudo systemctl edit husn-backend     # add HUSN_DEEPSEEK_KEY + HUSN_SMTP_PASSWORD
sudo systemctl restart husn-backend
journalctl -u husn-backend -f
```

---

## What's inside

### 🧠 AI engine (two layers)
- **Layer 1 — Statistical**: `IsolationForest` (anomaly score) + `XGBClassifier` (label) over 17 flow features. Output: `BENIGN / DDoS / PortScan / Brute Force / Infiltration / Web Attack` with confidence + SHAP explanation.
- **Layer 2 — Content**: 27 compiled regex patterns covering SQLi, XSS, command/code injection, reverse shells, path traversal, file inclusion, SSRF, XXE, **log4shell / Spring4Shell / SSTI**, scanner UAs (sqlmap/nuclei/nikto), sensitive paths (`.env`, `.git`, `/.aws/credentials`), webshells, weak/default credentials, HTTP smuggling, NoSQLi, LDAP injection, LOLBins (encoded PowerShell, certutil decode).
- **National Defense Mode** lowers the anomaly threshold deterministically (no random flips).
- **Adaptive Self-Learning** counter + decaying learning rate as flows pass through.

### 🛡 Active defense
- `DefenseResponse.block_ip()` either logs (dev) or `iptables -A INPUT -s <ip> -j DROP` (prod). Toggle: `response.real_iptables` in `config.yml`.
- CIDR-aware whitelist of never-blocked sources.
- Country-level allow / deny lists with auto-promotion to "Country Block" verdicts.
- Optional auto-unblock after `block_duration_seconds`.
- Per-IP throttle (`notify.throttle_seconds`) so a flood doesn't spam your inbox.

### 📡 Live sniffer + flow scoring
- Scapy-based; captures packets matching the BPF filter, builds bidirectional flows, projects them into the 17-D feature vector.
- Two memory rings: `recent_predictions` (200 entries, light) for general dashboard widgets, `recent_packets` (60 entries, rich, with feature dump + payload preview + signature match) for the **AI Inspector** tab.
- Captures the first 128 payload bytes per flow as a printable preview.

### 🪤 Honeypot
- Stdlib socket listener on configured ports, logs every probe with src IP + payload preview + service hint. Each connection is fed into `DefenseResponse` for blocking.

### 📧 Notifications
- Pure-stdlib SMTP (SSL or STARTTLS), gracefully no-ops when disabled.
- Severity-themed HTML email with **inlined SHAP chart** (CID PNG, headless Matplotlib).
- Bilingual "what this means" block, recommended-actions checklist, CTA button (Outlook VML fallback).
- Recipients editable at runtime from the dashboard (`/recipients`).
- Per-IP throttling so a 1000-packet flood doesn't fire 1000 emails.

### 📨 Email-driven SOC helper *(new)*
- IMAP poller picks up emails sent to your Manee mailbox.
- **Authorized-sender allowlist** — combines `inbox.allowed_senders` in config + the dashboard's recipient list. Anyone else is silently dropped.
- **Slash commands**: `/status`, `/blocked`, `/whitelist <ip>`, `/blacklist <ip>`, `/block <ip>`, `/unblock <ip>`, `/investigate <ip>`, `/scan <host>`, `/pause <secs>`, `/help`.
- Mixed mode — the body can include both commands and natural language. Commands execute first, then the LLM writes a friendly summary.
- Per-sender memory: each email address gets its own LLM session.
- Configurable poll interval (default 60s); manual trigger via `POST /inbox/poll`.

### 💬 SOC Analyst chatbot
- DeepSeek LLM via the OpenAI-compatible SDK.
- Every turn rebuilds a fresh system prompt that includes a live snapshot of the box (uptime, blocked IPs, sniffer state, recent attack labels).
- Bilingual responses, follows the language the user wrote in.
- Per-session history (last 6 turns).

### 🔧 Auto Patch *(new)*
A static analyzer + LLM-assisted patcher for **your own source code**.
- **13 vulnerability rules**: `eval`/`exec`, pickle deserialization, weak hashes, hardcoded secrets, subprocess `shell=True`, SQL f-strings, permissive CORS, debug-mode YAML, JS `eval` and `.innerHTML`.
- **Side-by-side diff view**: red/green per-line, exactly what would change.
- **3 admin actions**: Apply templated fix · Manual edit · Reject (logged with reason).
- **LLM Suggest** button with a hardened 11-rule system prompt that knows the project invariants (never remove bcrypt, never change function signatures, refuse with `NEEDS_MULTI_LINE` if uncertain).
- **Bulk fix with AI**: select multiple issues, fire LLM-suggest + apply for each sequentially. Live progress + results modal.
- **Backup before every write** at `<file>.husn-bak.<unix-ts>` + SHA-256 of before/after recorded in `/etc/husn/autopatch-history.jsonl`.
- **Whole-project tarball backups** with one click — listed, downloadable, deletable from the dashboard.

### 🎯 Kill Chain Visualizer
- 7-stage Lockheed Martin chain mapped from real detections.
- Each orb scales by detection count; pulse + connector animation when adjacent stages are active.
- Click a stage → severity mix bars, dominant SHAP signal, source IP list with Investigate buttons.

### 🌐 Topology Graph
- d3-force radar with the host at center, animated radar rings, red particles flowing along blocked links.
- Click a node → side drawer with country, connection count, attack type, Investigate.
- Live stats strip (nodes / blocked / countries / top country).
- Smooth at 50+ nodes — d3-force tuning, label background pills, FPS-throttled pulse.

### 🌍 Bilingual UI
- React 19 + TypeScript + Vite 8 + Tailwind v4 + Framer Motion + Recharts.
- Sidebar grouped into **Home · Network · Defense · Analysis · Admin** sections, accordion behavior (one section open at a time).
- Language toggle in the header (next to mute) — instant flip with full RTL layout, font swap, logo swap.
- Mobile drawer with backdrop on phones, slim icon column on tablets.

### 🔐 Auth + audit
- bcrypt password hashing (12 rounds), JWT with PyJWT (8h TTL).
- Server-side per-IP rate limit on `/auth/login`.
- Client-side soft lockout after 5 failed attempts (sessionStorage, 30s).
- Caps Lock detection, password strength meter, confirm-password, common-password blocklist.
- Append-only audit log of every login, user create/delete with IP + UA.

### 🖥 Web Terminal (admin only)
- 8 whitelisted CLI commands run in-process: `sysinfo · status · blocked · ports · services · procs · scan · check`.
- Rich-rendered output, no shell escape — `cat`/`rm`/`tar` etc. don't work.

### 🔄 Self-update channel
- Git-based check & apply. Refuses dirty trees, refuses non-fast-forward.
- APScheduler runs `check` every 5 min; `auto_apply: true` pulls automatically.

---

## Live demo runbook

The on-stage flow tested with judges:

1. **Open the dashboard** at the demo URL. Toggle EN/AR via the header globe button.
2. **Pre-fire attacks** from the attacker laptop (~30s before pitch start):
   ```bash
   python attacker-kit/demo_attack.py --target 16.171.230.111 --slow
   ```
3. **AI Inspector tab** — live rows of log4shell, SQLi, command injection, scanner UAs. Each row's payload preview shows the exact attack string. Expand for full features + signature pill.
4. **Kill Chain tab** — the radar shows which stages the attackers reached. None reached Installation.
5. **Email tab** (your inbox) — incident report arrived in seconds with SHAP chart inlined.
6. **Topology tab** — red satellites with animated red particles flowing toward the host. Click one → side drawer with the country flag and Investigate.
7. **Auto Patch tab** — 13 issues found in our own source. Expand `py-eval`. Apply Auto Fix → green check. Backup file written.
8. **Email Manee from your phone**: `/block 198.51.100.99` and "what's the biggest risk right now?" → 60s later, a styled HTML reply with the action confirmed and an LLM analysis.

---

## Configuration reference

All runtime settings live in `/etc/husn/config.yml` (production) or
`config/config.yml` (local override). See `config/config.example.yml` for the
full annotated template. Secrets only via env vars — any key ending in
`_env` names the env var to read.

```yaml
domain: manee.your-org.sa

smtp:
  enabled: true
  host: smtp.hostinger.com
  port: 465
  use_ssl: true
  user: manee@your-org.sa
  password_env: HUSN_SMTP_PASSWORD
  from_addr: "Manee Defender <manee@your-org.sa>"

inbox:
  enabled: true
  imap_host: imap.hostinger.com
  imap_port: 993
  folder: INBOX
  interval_seconds: 60
  allowed_senders:                      # who can email-drive Manee
    - admin@your-org.sa

llm:
  provider: deepseek
  model: deepseek-chat
  api_key_env: HUSN_DEEPSEEK_KEY
  temperature: 0.4
  max_tokens: 1024

response:
  real_iptables: true                   # actual kernel-level blocks
  block_duration_seconds: 3600
  whitelist: [127.0.0.1, 10.0.0.0/8]

notify:
  throttle_seconds: 60
  attach_shap_chart: true

defense:
  allowlist_ips:    [your.admin.ip.here]
  allowlist_countries: [SA]
  blocklist_countries: [KP, RU]

updater:
  enabled: true
  interval_minutes: 5
  auto_apply: false
  branch: main
```

---

## File layout

```
manee/
├── install-manee.sh              ★ universal installer (auto-detect OS)
├── install.sh / uninstall.sh     legacy installer (Ubuntu/Debian/RHEL)
├── run.py                        local dual-mode launcher
├── tab-recommender.sh            UI audit tool
├── exploit.py / exploit_demo.py  judges-day attack scripts
├── manee.png / manee_ar.png      brand logos (EN + AR)
├── sheild.png                    favicon
├── README.md / CLAUDE.md
├── config/
│   └── config.example.yml
├── deploy/
│   ├── husn-backend.service      systemd units
│   ├── husn-frontend.service
│   ├── husn-vuln.service
│   └── nginx-husn.conf
├── attacker-kit/
│   ├── demo_attack.py            ★ cinematic 14-attack live demo (Rich UI)
│   ├── exploit.py
│   └── README.md
├── backend/
│   ├── main.py                   FastAPI surface (~50 endpoints)
│   ├── vuln_app.py               *intentionally* vulnerable demo target
│   ├── requirements.txt
│   └── husn/src/
│       ├── ai/
│       │   ├── model.py          XGBoost + IsolationForest + SHAP
│       │   ├── data_gen.py       synthetic training data
│       │   └── signatures.py     ★ 27-rule payload scanner
│       ├── auth/                 bcrypt + JWT + per-IP rate limit
│       ├── core/
│       │   ├── response.py       DefenseResponse — iptables chokepoint
│       │   ├── lists.py          IP / country whitelist+blacklist
│       │   └── simulator.py
│       ├── chat/
│       │   └── chatbot.py        ★ live-state-grounded SOC LLM
│       ├── llm/                  shared OpenAI-compatible client
│       ├── sniffer/              live Scapy capture + flow scoring
│       ├── honeypot/             stdlib socket listener
│       ├── intel/                geoip + reputation
│       ├── learning/             SQLite store + retrainer
│       ├── notify/
│       │   ├── mailer.py         SMTP delivery
│       │   ├── report.py         ★ severity-themed HTML email
│       │   ├── auto_reports.py   APScheduler periodic reports
│       │   ├── inbox.py          ★ IMAP-driven SOC helper
│       │   ├── settings.py
│       │   └── explanation.py    bilingual "what this means"
│       ├── autopatch/            ★ static analyzer + LLM-assisted patcher
│       │   ├── rules.py          13 vulnerability rules
│       │   ├── scanner.py
│       │   ├── engine.py         apply / manual / reject / llm-suggest
│       │   ├── history.py        SHA-256-audited JSONL log
│       │   └── backups.py        whole-project tarballs
│       ├── system/               psutil-based hardware/network telemetry
│       ├── updater/              git-based self-updater
│       ├── config.py
│       └── cli.py                Typer CLI (also runs in the web Terminal)
└── frontend/                     React 19 + Vite 8 + Tailwind v4
    ├── index.html
    ├── package.json
    ├── public/
    │   └── husn-logo.png
    └── src/
        ├── App.tsx               main dashboard component (~2500 lines)
        ├── i18n.ts               EN + AR translation keys
        ├── index.css             Tailwind theme + custom CSS
        ├── assets/               logos
        └── components/
            ├── KillChainVisualizer.tsx
            ├── AIInspector.tsx
            └── AutoPatch.tsx
```

---

## Tech stack at a glance

| Layer | Choice |
|---|---|
| Backend language | Python 3.9+ |
| Web framework | FastAPI + Uvicorn (async) |
| AI | XGBoost · scikit-learn · SHAP · NumPy · pandas |
| Packet capture | Scapy (raw sockets via `cap_net_raw`) |
| LLM | DeepSeek (via OpenAI-compatible SDK), swappable |
| Auth | PyJWT + bcrypt |
| Email | stdlib smtplib · imaplib + Matplotlib (SHAP chart) |
| Scheduler | APScheduler (auto-reports, updater) + threading.Thread (inbox) |
| Static analysis | Pure-Python regex (no Bandit/Semgrep dependency) |
| Frontend | React 19 + TypeScript + Vite 8 + Tailwind v4 |
| Animation | Framer Motion (sidebar, kill chain orbs) |
| Charts | Recharts (traffic, gauges) + react-force-graph-2d (topology) |
| Markdown | react-markdown + remark-gfm (chat) |
| Process management | systemd (with security hardening drop-ins) |
| Reverse proxy | nginx (optional, for HTTPS via Let's Encrypt) |

---

## Security design choices

| Decision | Why |
|---|---|
| Two-layer detection (ML + signatures) | One layer's miss is caught by the next |
| **Honest** about what the AI does | XGBoost detects flow anomalies; signatures detect content; neither pretends to be the other. The Auto Patch LLM is rule-assisted, not a magic source-code-aware AI. |
| Backups before every write | One-command recovery from any patch mistake |
| Append-only audit logs | `/etc/husn/autopatch-history.jsonl` records every action with SHA-256 hashes |
| Path sandboxing in Auto Patch | Refuses any file outside the project root via `Path.relative_to()` |
| Capability minimalism | `setcap` on the venv Python only; no setuid, no root daemon |
| Authorized sender allowlist on email helper | The SOC helper can take destructive actions; only configured emails can drive it |
| Fail-closed on empty allowlist | If the allowlist is empty, **nobody** can email-drive Manee |
| SMTP throttling per source IP | A flood of attacks doesn't translate into a flood of emails |
| systemd hardening | `NoNewPrivileges`, `ProtectSystem=strict`, narrow `ReadWritePaths` |
| LLM never auto-applies | Even Bulk-Fix-with-AI shows a confirmation modal first |
| LLM client timeout | 75s server-side cap so a stuck DeepSeek call doesn't hang an HTTP worker |

---

# منيع · Manee — الدرع السيبراني الذكي

نظام دفاع سيبراني قابل للنشر، يجمع بين محرك ذكاء اصطناعي هجين (XGBoost + IsolationForest + SHAP)، وماسح توقيعات للحمولات، وحظر فعلي عبر iptables، ومحلل SOC بـ DeepSeek، ومُصلِّح آلي يقترح إصلاحات لكودنا المصدري.

## التشغيل

**محلياً:**
```bash
sudo bash install-manee.sh
python run.py both
```

**على خادم إنتاج:**
```bash
sudo bash install-manee.sh
sudo systemctl edit husn-backend       # أضف HUSN_DEEPSEEK_KEY و HUSN_SMTP_PASSWORD
sudo systemctl restart husn-backend
```

## المميزات

- 🧠 **كشف بطبقتين** — ذكاء سلوكي (XGBoost) + ٢٧ توقيع للحمولات (log4shell · SQLi · RCE · XSS · …)
- 🎯 **مرئيات سلسلة الهجوم** — يعرض إلى أين وصل المهاجم في سلسلة Lockheed Martin السباعية
- 🔍 **مفتش الذكاء** — بث مباشر لكل حزمة فحصها الذكاء مع الميزات الـ١٧ والحمولة
- 💬 **محلل SOC** — نموذج DeepSeek مرتبط بحالة النظام الحية، ثنائي اللغة
- 🔧 **التصحيح التلقائي** — تحليل ثابت + LLM يقترح إصلاحات لكودك، بنسخ احتياطية محسوبة بـ SHA-256
- 📨 **مساعد SOC عبر البريد** — أرسل بريداً لـ `manee@`، ينفّذ الأوامر (`/block` `/whitelist` `/investigate`) ويرد بتحليل
- 🛡 **حظر فعلي** على مستوى الكيرنل (iptables) مع قائمة سماح ذكية
- 📧 **تنبيهات بريدية** بتصميم متجاوب مع رسم SHAP مدمج
- 🌐 **واجهة عربية كاملة** بتبديل فوري بين العربية والإنجليزية

## التقنيات

Python 3.9+ · FastAPI · XGBoost · scikit-learn · SHAP · Scapy · DeepSeek · React 19 · TypeScript · Tailwind v4 · systemd · iptables

---

<div align="center">
  <p><b>منيع لا يُخترَق</b></p>
  <p><i>The fortress that cannot be breached</i></p>
  <br/>
  <p><sub>Built for DefensThon 2026 · Saudi Arabia</sub></p>
</div>
