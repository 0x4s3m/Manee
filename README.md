<div align="center">

<img src="manee.png" alt="Manee" width="120"/>

# Manee · منيع

**Intelligent Cyber Defense System**

*Two-layer threat detection · Real-time iptables enforcement · LLM-powered SOC analyst · Source-level auto-patching*

[![DefensThon 2026](https://img.shields.io/badge/DefensThon-2026-red?style=flat-square)](https://defensthon.sa)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

</div>

---

## Overview

**Manee** (Arabic: *منيع*, "impregnable") is a deployable cyber-defense system designed for production environments. It combines behavioural ML, content-level signature analysis, and large-language-model reasoning into a single bilingual control plane that protects, explains, and remediates — end to end.

The system is built on a defence-in-depth philosophy: every attack passes through multiple independent layers, every action is audit-logged with cryptographic hashes, and every administrative interface is gated by both server-side rate limits and client-side soft locks.

---

## Capabilities

| Capability | Implementation |
|---|---|
| **Behavioural detection** | XGBoost classifier + Isolation Forest anomaly detector over 17 named flow features |
| **Content detection** | 27 compiled regex signatures (SQLi, XSS, RCE, log4shell, Spring4Shell, scanners, weak credentials, LOLBins) |
| **Active response** | Real-time `iptables -A INPUT -s <ip> -j DROP` (toggleable; off by default) |
| **Explainability** | SHAP TreeExplainer with per-decision feature importance, surfaced inline in alerts |
| **SOC chatbot** | DeepSeek-powered assistant grounded in live system snapshot (bilingual EN/AR) |
| **Email-driven SOC** | IMAP-monitored mailbox with sender allowlist and slash-command actions |
| **Auto Patch** | Static analyzer (13 rules) + LLM-assisted patches with SHA-256-audited backups |
| **Kill chain visualization** | Live mapping of detections to the seven Lockheed Martin stages |
| **Honeypot** | Decoy listener on configurable ports, integrated with the response pipeline |
| **Self-update** | Git-based with safety gates against dirty trees and non-fast-forward pulls |
| **Bilingual UI** | Full English/Arabic with RTL layout, Noto Sans Arabic typography |
| **Mobile responsive** | Drawer sidebar on phones, slim icon column on tablets, full layout on desktop |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          DASHBOARD (React 19)                           │
│  Home · Network · Defense · Analysis · Admin                            │
└─────────────────┬───────────────────────────────────────────────────────┘
                  │ HTTPS · JWT Bearer auth
                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     FASTAPI BACKEND (uvicorn)                           │
│                                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Detection   │  │ Defense      │  │ Notify       │  │ Auto Patch   │ │
│  │             │  │              │  │              │  │              │ │
│  │ • XGBoost   │  │ • iptables   │  │ • SMTP       │  │ • Scanner    │ │
│  │ • IsoForest │  │ • Whitelist  │  │ • SHAP chart │  │ • LLM advisor│ │
│  │ • SHAP      │  │ • Country    │  │ • IMAP-driven│  │ • Backups    │ │
│  │ • 27 sigs   │  │   lists      │  │   helper     │  │ • Audit log  │ │
│  └─────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Sniffer     │  │ Honeypot     │  │ Auth         │  │ LLM client   │ │
│  │ Scapy live  │  │ Socket trap  │  │ bcrypt + JWT │  │ DeepSeek     │ │
│  └─────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  systemd  ·  iptables  ·  /etc/husn  ·  /var/log/husn                   │
└─────────────────────────────────────────────────────────────────────────┘
```

Three separately-managed processes:

| Service | Port | Purpose |
|---|---|---|
| `husn-backend` | 8000 | FastAPI surface, AI engine, schedulers |
| `husn-frontend` | 5173 | React dashboard (static dist) |
| `husn-vuln` | 9000 | Deliberately vulnerable demo target |

---

## Installation

### Universal installer (recommended)

The installer auto-detects the host operating system, installs all dependencies, builds the Python virtual environment, bootstraps the AI models, builds the React production bundle, registers systemd units with security hardening, and grants the necessary capabilities for raw packet capture and iptables manipulation.

```bash
git clone https://github.com/0x4s3m/husn.git
cd husn
sudo bash install-manee.sh
```

**Supported platforms** (via OS auto-detection):

| Family | Distributions | Package manager |
|---|---|---|
| Debian | Ubuntu 20.04+, Debian 11+, Kali, Linux Mint, Pop!_OS, Raspbian | `apt-get` |
| RHEL | Fedora 36+, Rocky 9+, AlmaLinux 9+, RHEL 9+, Amazon Linux 2023 | `dnf` / `yum` |
| Arch | Arch Linux, Manjaro, EndeavourOS, Garuda | `pacman` |
| Alpine | Alpine 3.18+ | `apk` |
| macOS | Apple Silicon + Intel | `brew` (development only — no iptables) |

### Optional environment variables

```bash
sudo MANEE_DOMAIN=defense.example.sa MANEE_WITH_NGINX=yes bash install-manee.sh
```

| Variable | Default | Effect |
|---|---|---|
| `MANEE_DOMAIN` | _(unset)_ | Public domain for nginx + Let's Encrypt |
| `MANEE_WITH_NGINX` | `no` | Configures nginx reverse proxy if `yes` |
| `MANEE_INSTALL_DIR` | `/opt/husn` | Installation prefix |
| `MANEE_SERVICE_USER` | `husn` | System user that runs the services |
| `MANEE_SKIP_BUILD` | `0` | Skip frontend build (use existing `dist/`) |
| `MANEE_SKIP_TRAIN` | `0` | Skip AI model bootstrap (faster reinstall) |
| `MANEE_NONINTERACTIVE` | `0` | CI mode — no prompts |

### Post-install configuration

```bash
# Add API key + SMTP credentials via systemd drop-in
sudo nano /etc/systemd/system/husn-backend.service.d/secrets.conf
```

```
[Service]
Environment=HUSN_DEEPSEEK_KEY=sk-...
Environment=HUSN_SMTP_PASSWORD=...
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart husn-backend
```

Then access the dashboard at `http://<host>:5173` and authenticate with `admin` / `admin@`. Change the password immediately via **Admin → Users**.

### Local development

For laptop demos and contributor work:

```bash
git clone https://github.com/0x4s3m/husn.git
cd husn
sudo bash install-manee.sh   # one-time setup
python run.py both           # starts all three services
```

Access:
- Dashboard: http://localhost:5173
- API documentation: http://localhost:8000/docs
- Vulnerable target: http://localhost:9000

---

## Detection Engine

### Layer 1 — Statistical analysis

A hybrid model trained on synthetic flow telemetry generates two parallel signals:

1. **`IsolationForest`** computes an anomaly score per flow. Threshold defaults to `0.0`; National Defense Mode lowers it to `0.10` to capture borderline samples.
2. **`XGBClassifier`** assigns one of six labels: `BENIGN`, `DDoS`, `PortScan`, `Brute Force`, `Infiltration`, `Web Attack`.
3. **`shap.TreeExplainer`** decomposes each verdict into per-feature contributions, surfaced both in the dashboard and embedded as a CID-inlined chart in alert emails.

The seventeen features consumed by both models:

```
flow_duration       total_fwd_pkts      total_bwd_pkts
fwd_pkt_len_max     fwd_pkt_len_min     fwd_pkt_len_mean
bwd_pkt_len_max     bwd_pkt_len_min     bwd_pkt_len_mean
flow_byts_s         flow_pkts_s         flow_iat_mean
flow_iat_max        pkt_len_mean        pkt_len_std
ack_flag_cnt        syn_flag_cnt
```

### Layer 2 — Content signatures

A library of 27 compiled regular expressions inspects the first 128 bytes of each flow's payload. Matches override the statistical verdict deterministically — content evidence outranks behavioural inference.

| Category | Coverage |
|---|---|
| **SQL injection** | Classic, destructive, MSSQL `xp_cmdshell`, `LOAD_FILE` / `INTO OUTFILE` |
| **Cross-site scripting** | Reflected (`<script>`, `javascript:`, event handlers), DOM (`document.cookie`, `<svg onload>`) |
| **Command injection** | Shell metacharacters with binaries (`cat`, `wget`, `nc`), `$()` and backtick substitution |
| **Reverse shells** | `bash -i`, `/dev/tcp/`, `nc -e`, `mkfifo /tmp/`, Python `socket`/`pty` patterns |
| **Path traversal** | `../`, encoded variants (`%2e%2e%2f`, `%252e`), sensitive file targets |
| **File inclusion** | LFI/RFI via `?file=`, `?page=`, `php://`, `data://`, `expect://` |
| **SSRF** | Private IP ranges, `169.254.169.254`, `file://`, `gopher://`, `dict://` |
| **XXE** | External entity declarations |
| **Log4Shell / JNDI** | `${jndi:...}` with all known bypass forms (`${env:`, `${lower:`, `${::-j}`) |
| **SSTI / Spring4Shell** | `class.module.classLoader`, template-engine arithmetic, runtime exec |
| **Scanner fingerprints** | sqlmap, nuclei, nikto, wpscan, masscan, ffuf, gobuster, hydra, nessus |
| **Sensitive paths** | `.env`, `.git/`, `.aws/credentials`, `.ssh/id_rsa`, `/wp-admin`, `/actuator` |
| **Webshells** | PHP `<?php system`, JSP `cmd.jsp`, ASPX command shells, c99/r57/b374k |
| **Brute force** | Common weak credentials and default username/password combinations |
| **HTTP smuggling** | Conflicting `Transfer-Encoding` and `Content-Length` headers |
| **NoSQL injection** | MongoDB operators (`$ne`, `$where`, `$regex`) |
| **LDAP injection** | Filter syntax exploitation |
| **LOLBins** | Encoded PowerShell, `certutil -decode`, `bitsadmin /transfer`, `mshta`, `regsvr32` |

---

## Threat Intelligence

Manee's signature library tracks publicly-disclosed vulnerabilities (CVEs) and is extended whenever new high-impact entries are published. Each detection rule is backed by one or more CVE references, so an alert is always traceable to a specific known-exploit pattern.

### Current CVE coverage

| Signature ID | Vulnerability class | CVE reference |
|---|---|---|
| `log4shell_jndi` | Log4j 2.x JNDI injection | [CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228) · [CVE-2021-45046](https://www.cve.org/CVERecord?id=CVE-2021-45046) · [CVE-2021-45105](https://www.cve.org/CVERecord?id=CVE-2021-45105) |
| `template_injection` | Spring4Shell (Spring Framework RCE) | [CVE-2022-22965](https://www.cve.org/CVERecord?id=CVE-2022-22965) |
| `xxe_external_entity` | XML External Entity processing | [CVE-2014-3660](https://www.cve.org/CVERecord?id=CVE-2014-3660) · [CVE-2017-9233](https://www.cve.org/CVERecord?id=CVE-2017-9233) |
| `ssti` | Jinja2 / Twig / Freemarker / Spring SpEL | [CVE-2016-10745](https://www.cve.org/CVERecord?id=CVE-2016-10745) · [CVE-2019-8341](https://www.cve.org/CVERecord?id=CVE-2019-8341) |
| `path_traversal` · `sensitive_file_read` | Generic path-traversal pattern | [CVE-2007-3304](https://www.cve.org/CVERecord?id=CVE-2007-3304) and family |
| `file_inclusion` | Local/Remote File Inclusion (LFI/RFI) | [CVE-2018-19518](https://www.cve.org/CVERecord?id=CVE-2018-19518) and family |
| `ssrf_probe` | Server-Side Request Forgery | [CVE-2019-5736](https://www.cve.org/CVERecord?id=CVE-2019-5736) and family |
| `lolbin_abuse` | Encoded PowerShell / certutil decode / bitsadmin | LOLBAS techniques (T1218, T1027) |
| `http_smuggle` | HTTP request smuggling (CL.TE / TE.CL) | [CVE-2019-18278](https://www.cve.org/CVERecord?id=CVE-2019-18278) · [CVE-2019-20372](https://www.cve.org/CVERecord?id=CVE-2019-20372) |
| `webshell` | PHP / JSP / ASPX backdoor uploads | Multiple — `c99shell`, `r57shell`, `b374k` family |
| `nosql_injection` | MongoDB operator injection | [CVE-2021-21803](https://www.cve.org/CVERecord?id=CVE-2021-21803) |
| `sqli_classic` · `sqli_destructive` | SQL injection (UNION-based, error-based, blind) | OWASP Top 10 — A03:2021 |
| `xss_reflected` · `xss_dom` | Cross-site scripting | OWASP Top 10 — A03:2021 |
| `cmd_injection` · `reverse_shell` | OS command injection | OWASP Top 10 — A03:2021 |

### How new CVEs are integrated

When a new high-impact CVE is published, the integration workflow is:

1. **Pattern extraction** — exploit payloads from public PoCs are converted into a tight regex.
2. **Rule definition** — a new entry is added to `backend/husn/src/ai/signatures.py`:
   ```python
   (r"(?i)<your-pattern>",
    "rule_name", "Web Attack", "Critical", 0.94),
   ```
3. **CVE link** — the CVE reference (e.g. `https://www.cve.org/CVERecord?id=CVE-2024-XXXXX`) is recorded as a comment above the rule and added to this README table.
4. **Validation** — the rule is tested against the public PoC and against a benign-traffic corpus to verify zero false positives.
5. **Deployment** — pushed via the standard update channel (`updater` service) — no service restart required.

### Roadmap: CVE feed automation

Planned for the next major release: an automated CVE intake worker that polls the [NVD JSON 2.0 feed](https://nvd.nist.gov/developers/vulnerabilities) for new entries with **CVSS ≥ 7.0** in active exploit categories (RCE, deserialization, injection), proposes draft signature rules via the LLM, and queues them for administrator review through the **Auto Patch** interface — closing the loop from public disclosure to live detection in under an hour.

---

## Response Pipeline

Detection events flow through a single chokepoint, `DefenseResponse.block_ip()`:

1. **Whitelist check** — CIDR-aware; refuses to block whitelisted sources
2. **Country policy** — promotes verdict to `Country Block` for blacklisted regions
3. **Kernel-level enforcement** — `iptables -A INPUT -s <ip> -j DROP` (production) or memory-only logging (development)
4. **Persistence** — written to in-memory registry, exposed via `/blocked` API
5. **Auto-expiry** — optional timer for `iptables -D` after configurable duration
6. **Learning store** — recorded to SQLite for retraining
7. **Notification** — incident report emitted to disk and (throttled) email

Real iptables enforcement is **disabled by default**. Enable it via:

```yaml
response:
  real_iptables: true
  block_duration_seconds: 3600
  whitelist:
    - 127.0.0.1
    - 10.0.0.0/8
```

⚠️ Always whitelist administrative IPs before enabling real enforcement.

---

## Auto Patch

A static analyzer for the project's own source code, paired with an LLM-assisted patch advisor.

**Workflow:**
1. Scanner walks the project tree (`backend/`, `frontend/src/`, `config/`, `deploy/`)
2. Each file is matched against the rule library — pattern + suggested fix template + rationale
3. Findings appear in the dashboard with a side-by-side diff view
4. Administrator chooses one of three actions per finding:
   - **Apply** — writes the templated fix
   - **Ask LLM** — DeepSeek proposes a custom one-line patch (governed by an 11-rule safety prompt)
   - **Manual edit** — admin writes the replacement directly
5. Every write creates a timestamped backup (`<file>.husn-bak.<unix-ts>`)
6. SHA-256 of before and after recorded in append-only audit log
7. Python files are validated with `ast.parse()` post-write; syntactically broken patches are reverted automatically

Bulk operations: select multiple findings, run `Ask LLM + Apply` sequentially with progress tracking and a results summary.

**Available rules:**

| ID | Rule | Severity |
|---|---|---|
| `py-eval` | `eval()` in Python | Critical |
| `py-exec` | `exec()` in Python | Critical |
| `py-pickle-loads` | Insecure deserialization | Critical |
| `py-subprocess-shell` | `subprocess(shell=True)` | High |
| `py-md5` | Weak hash (MD5) | Medium |
| `py-random-secrets` | `random.random()` in security context | High |
| `py-hardcoded-secret` | API key literal in source | High |
| `py-sql-fstring` | SQL built with f-string | Critical |
| `py-cors-wildcard` | `allow_origins=['*']` | High |
| `yaml-debug-true` | `debug: true` in production config | Medium |
| `yaml-cors-wildcard` | Wildcard CORS in YAML | High |
| `ts-eval` | `eval()` in JavaScript/TypeScript | Critical |
| `ts-innerhtml` | `.innerHTML` assignment | High |

---

## Email-Driven SOC Helper

External operators may interact with Manee by email. The system polls IMAP every 60 seconds, parses authorized messages, and replies with an LLM-generated SOC analyst response.

**Slash commands** are recognized at the start of any line in the email body:

| Command | Action |
|---|---|
| `/help` | List all available commands |
| `/status` | System snapshot — sniffer, honeypot, blocked count |
| `/blocked` | List currently blocked IPs |
| `/whitelist <ip>` | Add to allow-list |
| `/blacklist <ip>` | Add to deny-list |
| `/block <ip>` | Block immediately (manual) |
| `/unblock <ip>` | Release a kernel-level block |
| `/investigate <ip>` | Geographic + reputation + block status |
| `/scan <host>` | Network scan |
| `/pause <seconds>` | Pause email alerts |

**Authorization** combines two sources: explicit `inbox.allowed_senders` in configuration plus the dashboard's notification recipients. Any email from outside this combined allowlist is silently discarded — no rejection notice is sent (avoiding both information leakage and SMTP quota waste).

Each sender receives a per-address conversational session, allowing follow-up questions in the same thread to retain context.

---

## Configuration Reference

All runtime configuration lives in `/etc/husn/config.yml`. Secrets are referenced via `*_env` keys that name environment variables — values are never stored in YAML.

```yaml
# Public-facing identity
domain: defense.example.sa

# Outbound mail
smtp:
  enabled: true
  host: smtp.hostinger.com
  port: 465
  use_ssl: true
  user: manee@example.sa
  password_env: HUSN_SMTP_PASSWORD
  from_addr: "Manee Defender <manee@example.sa>"

# Inbound mail (SOC helper)
inbox:
  enabled: true
  imap_host: imap.hostinger.com
  imap_port: 993
  folder: INBOX
  interval_seconds: 60
  allowed_senders:
    - admin@example.sa

# Language model
llm:
  provider: deepseek
  model: deepseek-chat
  api_key_env: HUSN_DEEPSEEK_KEY
  temperature: 0.4
  max_tokens: 1024

# Active defense
response:
  real_iptables: true
  block_duration_seconds: 3600
  whitelist:
    - 127.0.0.1
    - 10.0.0.0/8

# Defense lists
defense:
  allowlist_ips: [your.admin.ip]
  allowlist_countries: [SA]
  blocklist_countries: [KP, RU]

# Notification policy
notify:
  throttle_seconds: 60
  attach_shap_chart: true

# Auto-update
updater:
  enabled: true
  interval_minutes: 5
  auto_apply: false
  branch: main
```

---

## Project Structure

```
manee/
├── install-manee.sh          Universal OS-detecting installer
├── uninstall.sh              Clean removal (--purge for state too)
├── run.py                    Local development launcher
├── tab-recommender.sh        UI structure audit utility
├── README.md                 This document
├── CLAUDE.md                 Internal architecture notes
│
├── config/
│   └── config.example.yml    Annotated configuration template
│
├── deploy/
│   ├── husn-backend.service  systemd units with hardening
│   ├── husn-frontend.service
│   ├── husn-vuln.service
│   └── nginx-husn.conf       Reverse proxy template
│
├── attacker-kit/
│   ├── demo_attack.py        Cinematic 14-attack demonstration
│   ├── exploit.py
│   └── README.md
│
├── backend/
│   ├── main.py               FastAPI application surface (~50 endpoints)
│   ├── vuln_app.py           Intentionally vulnerable target
│   ├── requirements.txt
│   └── husn/src/
│       ├── ai/               XGBoost · IsolationForest · SHAP · 27 signatures
│       ├── auth/             bcrypt · JWT · per-IP rate limiting
│       ├── core/             DefenseResponse · runtime lists · simulator
│       ├── chat/             SOC analyst chatbot
│       ├── llm/              Shared OpenAI-compatible client
│       ├── sniffer/          Live Scapy capture + flow scoring
│       ├── honeypot/         Socket-based decoy listener
│       ├── intel/            GeoIP + reputation lookups
│       ├── learning/         SQLite store + retrainer
│       ├── notify/           SMTP · IMAP · reports · auto-summaries
│       ├── autopatch/        Static analyzer + patch engine + backups
│       ├── system/           Hardware + network telemetry
│       ├── updater/          Git-based self-update
│       └── cli.py            Typer CLI (also runs in the web Terminal)
│
└── frontend/
    ├── index.html
    ├── package.json
    ├── public/
    └── src/
        ├── App.tsx           Single-component dashboard
        ├── i18n.ts           EN + AR translation keys
        ├── index.css         Tailwind theme
        └── components/
            ├── KillChainVisualizer.tsx
            ├── AIInspector.tsx
            └── AutoPatch.tsx
```

---

## Technology Stack

| Layer | Components |
|---|---|
| **Backend** | Python 3.9+ · FastAPI · Uvicorn · APScheduler · PyYAML · PyJWT · bcrypt |
| **Machine learning** | XGBoost · scikit-learn (Isolation Forest) · SHAP · NumPy · pandas |
| **Network** | Scapy (raw capture) · stdlib `smtplib`/`imaplib`/`socket` |
| **LLM integration** | OpenAI Python SDK pointed at DeepSeek (provider-swappable) |
| **Charts** | Matplotlib (Agg backend, headless SHAP renders for email) |
| **Frontend** | React 19 · TypeScript · Vite 8 · Tailwind CSS v4 |
| **Animations** | Framer Motion · custom canvas (radar topology) |
| **Visualization** | Recharts · react-force-graph-2d · Lucide icons |
| **Markdown** | react-markdown · remark-gfm |
| **Infrastructure** | systemd · iptables · nginx (optional) · Let's Encrypt |

---

## Security Properties

| Property | Mechanism |
|---|---|
| Defense in depth | Two independent detection layers (statistical + content) |
| Principle of least privilege | `setcap cap_net_raw,cap_net_admin=eip` on the venv Python — no setuid, no root daemon |
| Secrets management | Environment variables only; no plaintext credentials in YAML |
| Audit trail | Append-only JSONL log of every Auto Patch action with SHA-256 hashes |
| Path sandboxing | Auto Patch refuses any file outside the project root via `Path.relative_to()` |
| Backups before mutation | Every patch and every project tarball recorded with timestamp |
| Syntax validation | `ast.parse()` post-write check with automatic rollback on failure |
| Sender allowlist | Email-driven SOC helper rejects all unauthorized addresses silently |
| Fail-closed defaults | Empty allowlist means no email driver; `real_iptables: false` by default |
| Rate limiting | Per-IP throttling on email sends and `/auth/login` |
| Soft client lockout | Browser-side counter on failed logins (sessionStorage) |
| LLM safety prompts | 11-rule system prompt forbids removing security operations |
| Manual approval gates | LLM never auto-applies patches; bulk mode requires explicit confirmation |
| systemd hardening | `NoNewPrivileges`, `ProtectSystem=strict`, narrow `ReadWritePaths` |
| Connection timeouts | 75s server-side, 90s client-side on LLM calls |

---

## Operations

### Service management

```bash
sudo systemctl status husn-backend
sudo systemctl restart husn-backend husn-frontend husn-vuln
journalctl -u husn-backend -f
```

### Command-line interface

```bash
sudo -u husn PYTHONPATH=/opt/husn/backend HUSN_CONFIG=/etc/husn/config.yml \
  /opt/husn/backend/venv/bin/python -m husn.src.cli
```

Available commands: `sysinfo`, `status`, `blocked`, `ports`, `services`, `procs`, `scan`, `check`.

The same dispatch table is exposed in the dashboard's **Admin → Terminal** tab.

### Backups

```bash
sudo ls -lh /etc/husn/backups/                           # list project tarballs
scp manee.example:/etc/husn/backups/...tar.gz ./         # download
sudo tar -xzf <file>.tar.gz -C /opt/husn/                # restore
```

### Update channel

```bash
# Check for updates without applying
sudo systemctl restart husn-backend
# or via the dashboard's auto-poll (every 5 minutes by default)
```

---

## Documentation

| File | Contents |
|---|---|
| `README.md` | This document |
| `CLAUDE.md` | Internal architecture notes (developer-facing) |
| `config/config.example.yml` | Fully-annotated configuration template |
| `attacker-kit/README.md` | Demo attack scripts documentation |
| `backend/README.md` | Backend module-level documentation |

---

## Roadmap

- [ ] Distributed deployment with shared learning store
- [ ] eBPF-based capture for 10×+ flow throughput
- [ ] Multi-tenant administration with role-scoped policies
- [ ] Integration with external SIEM platforms (Splunk, Elastic)
- [ ] Hardware-backed JWT signing
- [ ] Federated learning across multiple Manee instances

---

## Acknowledgments

Built for the **DefensThon 2026** national cybersecurity competition (Saudi Arabia).
This project would not exist without the open-source work of the FastAPI, scikit-learn, XGBoost, SHAP, React, Tailwind, and Scapy communities.

---

<div align="center">

**منيع لا يُخترَق**
*The fortress that cannot be breached*

</div>
