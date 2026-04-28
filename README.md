# Husn (حصن) — Intelligent Cyber Defense System

<div align="center">
  <h3>AI-powered defense for national infrastructure</h3>
  <p><b>DefensThon 2026 — Official Submission</b></p>
</div>

Husn is a deployable cyber-defense agent. It combines a hybrid AI engine
(IsolationForest + XGBoost + SHAP), real-time host telemetry, active
iptables-based blocking, and rich HTML email alerts into a single bilingual
dashboard. It runs equally well on a laptop for a live demo or as a hardened
systemd service on a public VPS.

---

## Two ways to run it

### 1. Local demo (Kali / Ubuntu / WSL2)
```bash
chmod +x setup.sh && ./setup.sh
python run.py both
```
- Dashboard: http://localhost:5173
- API:       http://localhost:8000
- Vuln target: http://localhost:9000
- Interactive CLI in the terminal

### 2. Production server install
```bash
sudo HUSN_DOMAIN=husn.your-org.sa HUSN_WITH_NGINX=yes ./install.sh
sudo nano /etc/husn/config.yml      # set SMTP + recipients
sudo systemctl edit husn-backend    # add HUSN_SMTP_PASSWORD env var
sudo certbot --nginx -d husn.your-org.sa
```
After install:
```
systemctl status husn-backend husn-frontend
journalctl -u husn-backend -f
sudo -u husn /opt/husn/backend/venv/bin/python -m husn.src.cli
```

---

## What's inside

### AI engine
- **IsolationForest** for unsupervised anomaly detection (zero-day-shaped traffic).
- **XGBoost classifier** labelling traffic as `BENIGN / DDoS / PortScan / Brute Force / Infiltration / Web Attack`.
- **SHAP** for per-decision feature importance — surfaced in the dashboard *and* embedded inline in alert emails.
- **Adaptive Self-Learning**: knowledge-base counter grows and learning-rate decays as traffic flows through.
- **National Defense Mode**: a one-click sensitivity boost that lowers the anomaly threshold and re-themes the UI to red.

### Active defense
- `DefenseResponse.block_ip()` either logs (dev) or shells out to `iptables -A INPUT -s <ip> -j DROP` (prod). Toggle via `response.real_iptables` in `config.yml`.
- Whitelist of never-blocked CIDRs (your laptop, monitoring, the gateway).
- Optional auto-unblock after `block_duration_seconds`.
- Per-IP throttle (`notify.throttle_seconds`) keeps a 1000-packet flood from sending 1000 emails.

### Host telemetry
- `/system/hardware`, `/system/ports`, `/system/processes`, `/system/network`, `/system/scan` — all `psutil`-driven, no external deps.
- Suspicious-process heuristics: known malware names, executables in `/tmp`/`/dev/shm`, untrusted-path binaries with active connections, cryptominer command-line signatures.
- TCP-connect scanner with optional `nmap -sV` upgrade if the binary is on PATH.

### Notifications
- SMTP (Gmail / Office365 / SES / self-hosted) — config-driven, gracefully degrades if disabled.
- HTML email with the SHAP feature-importance chart inlined as a CID image.
- Recipients editable at runtime from the dashboard.
- Reports also persisted as Markdown + HTML + JSON under `paths.reports_dir`.

### Self-update channel
- Git-based: `update` / `check` commands in CLI, mirror endpoints `/updates/check` and `/updates/apply`.
- Background scheduler runs `check` every 5 minutes (configurable). With `auto_apply: true` it pulls automatically; otherwise it just notifies.
- Refuses to overwrite a dirty working tree, refuses non-fast-forward pulls, and re-runs `pip install` only when `requirements.txt` actually changed.

### Bilingual dashboard
- React 19 + TypeScript + Tailwind v4 + Framer Motion + Recharts.
- Sidebar tabs: Dashboard · Host · Network · Detection · Simulation · XAI · Defense · Updates · Payloads.
- Full RTL Arabic mode with one-click toggle.

### Professional CLI
```
husn > sysinfo                # hardware + OS + interfaces
husn > ports                  # listening ports + owning process
husn > services               # one row per service
husn > procs --suspicious     # only the flagged ones
husn > scan 192.0.2.10        # nmap -sV / TCP-connect
husn > simulate               # run an attack
husn > blocked                # currently blocked IPs
husn > check                  # update check
husn > update                 # apply pending update
husn > report-test            # send a test email through SMTP
husn > status                 # holistic system status
```

---

## Live contest demo (judges)

This is the runbook for the on-stage demo against your VPS:

1. **Show the dashboard** at `https://your-domain.sa`. Toggle EN/AR.
2. **Open the Host tab** — judges see real CPU/RAM/disk, real listening ports, real processes. *This is not a mockup.*
3. **From your laptop**, run the exploit against the public VPS:
   ```bash
   python exploit_demo.py http://your-domain.sa:9000
   ```
4. **In the dashboard**:
   - Defense tab: a new blocked-IP entry appears, showing your laptop's source IP.
   - SIEM feed: the attack is classified.
   - Email: an alert lands in the recipients' inbox within seconds, with the SHAP chart inline.
5. **Judges can attempt to re-hit** the vuln endpoint from your laptop — it now times out, because iptables really dropped them.
6. **Open the Updates tab** and run `Check Now` to demonstrate the self-update channel is live.

---

## Configuration reference

All runtime settings live in `/etc/husn/config.yml` (production) or `config/config.yml` (local override). See `config/config.example.yml` for the full annotated template. Secrets live only in environment variables — any key ending in `_env` names the env var to read.

```yaml
domain: husn.your-org.sa
smtp:
  enabled: true
  host: smtp.gmail.com
  port: 587
  use_tls: true
  user: alerts@your-org.sa
  password_env: HUSN_SMTP_PASSWORD
  from_addr: "Husn Defender <alerts@your-org.sa>"
recipients: [admin@your-org.sa, soc@your-org.sa]
response:
  real_iptables: true
  block_duration_seconds: 3600
  whitelist: [127.0.0.1, 10.0.0.0/8]
notify:
  throttle_seconds: 60
  attach_shap_chart: true
updater:
  enabled: true
  interval_minutes: 5
  auto_apply: false
  repo_url: git@github.com:your-org/husn.git
  branch: main
```

---

## File layout

```
husn/
├── install.sh                         # production VPS installer
├── uninstall.sh
├── setup.sh                           # local-machine setup (apt + venv + npm)
├── run.py                             # local dual-mode launcher
├── docker-compose.yml + Dockerfile
├── config/config.example.yml
├── deploy/                            # systemd units + nginx template
│   ├── husn-backend.service
│   ├── husn-frontend.service
│   └── nginx-husn.conf
├── backend/
│   ├── main.py                        # FastAPI surface
│   ├── vuln_app.py                    # *intentionally* vulnerable demo target
│   └── husn/
│       └── src/
│           ├── ai/      model.py · data_gen.py
│           ├── core/    response.py · simulator.py
│           ├── system/  hardware · processes · network · scanner
│           ├── notify/  mailer · report
│           ├── updater/ updater
│           ├── config.py
│           └── cli.py
├── frontend/                          # React 19 + Tailwind 4 dashboard
└── exploit_demo.py                    # canned attack you'll run on stage
```

---

# حصن — الدرع السيبراني الذكي

نظام دفاع سيبراني قابل للنشر، يجمع بين محرك ذكاء اصطناعي هجين (IsolationForest + XGBoost + SHAP)، ومراقبة المضيف في الوقت الفعلي، وحظر فعلي عبر iptables، وتقارير بريد إلكتروني غنية، في لوحة تحكم ثنائية اللغة واحدة.

**التشغيل المحلي**: `./setup.sh && python run.py both`
**التثبيت على خادم إنتاجي**: `sudo HUSN_DOMAIN=husn.example.sa HUSN_WITH_NGINX=yes ./install.sh`

المميزات: وضع الدفاع الوطني · التعلم الذاتي التكيفي · شرح SHAP · حظر فعلي بـ iptables · تنبيهات بريدية فورية · تحديث ذاتي كل 5 دقائق · واجهة CLI احترافية · لوحة تحكم بالعربية والإنجليزية.
