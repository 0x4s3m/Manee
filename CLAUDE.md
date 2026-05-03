# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

**Manee (منيع)** is a competition submission for **DefensThon 2026**. It evolved from a single-machine demo into a **deployable server agent**: the same codebase runs as `python run.py both` on a laptop *and* installs to `/opt/husn` with systemd units on a VPS. The on-stage demo plan is to deploy to a public server and run `exploit_demo.py` from a laptop against the live install — judges watch the dashboard, the blocked-IP list, and the email inbox light up in real time.

> **Naming note:** the user-facing product name is **Manee (منيع)** — that's what appears in the UI title, email subjects, chatbot persona, and judge-facing materials. The repo, Python package (`husn/`), systemd units (`husn-backend`), install path (`/opt/husn`), env-var prefix (`HUSN_*`), and Linux user (`husn`) all still use the old internal name **Husn (حصن)**. Don't rename code paths; do use "Manee" in any new user-facing strings.

The narrative the system must sell is:

> **Real attack → AI detection → SHAP explanation → real iptables block → email alert with inline SHAP chart**

That flow crosses `frontend/src/App.tsx`, `backend/main.py`, `husn/src/ai/model.py`, `husn/src/core/response.py`, and `husn/src/notify/`. Changes that disrupt it are high-risk regardless of how clean they look in isolation.

## Repository layout note

The project root is `husn/` (one level below the outer `Husn/` folder). All commands assume `cwd = husn/`. `run.py`, `setup.sh`, `install.sh`, `Dockerfile`, and `docker-compose.yml` all expect to be invoked from there.

## Commands

### Local dev (from `husn/`)
```bash
python run.py both        # Backend (8000) + vuln_app (9000) + frontend (5173) + CLI
python run.py backend|frontend|cli|target|exploit
```
`run.py` sets `PYTHONPATH=backend` and runs the CLI as `python -m husn.src.cli` with `cwd=backend`. The `husn` package lives at `backend/husn/`, *not* the repo root — replicate this when invoking modules manually.

### Production install (root)
```bash
sudo HUSN_DOMAIN=foo.bar HUSN_WITH_NGINX=yes ./install.sh    # idempotent
sudo systemctl edit husn-backend                              # add HUSN_SMTP_PASSWORD env
journalctl -u husn-backend -f
sudo -u husn /opt/husn/backend/venv/bin/python -m husn.src.cli
./uninstall.sh [--purge]
```

### Tests
```bash
cd backend && PYTHONPATH=. python -m unittest husn.tests.test_core
cd backend && PYTHONPATH=. python -m unittest husn.tests.test_core.TestHusn.test_ai_prediction
```

### Frontend (from `frontend/`)
```bash
npm run dev | build | lint
```
`vite.config.ts` sets `publicDir: false`, which is why `npm run build` manually `cp`s favicon/icons into `dist/`.

## Architecture

### Three-process demo topology
1. **`backend/main.py`** (FastAPI :8000) — owns the `HusnAI` singleton, the in-memory `logs` list, the blocked-IP registry (via `responder`), the runtime recipient list, and the APScheduler 5-min update loop.
2. **`backend/vuln_app.py`** (FastAPI :9000) — *intentionally* vulnerable government-portal mock with command injection in `/ping`. **Do not "fix" it** — it's the target. On a public server, bind it to `127.0.0.1` only.
3. **`frontend/`** (Vite :5173) — polls `/monitor`, `/status`, `/logs` every 2s and `/system/*`, `/blocked`, `/recipients`, `/updates/status` every 5s.

`exploit_demo.py` runs the real RCE over HTTP *and* fires Scapy packets crafted with the feature signatures the AI is trained to flag. The HTTP call proves the exploit is real; the packets are what the AI actually detects.

### AI engine (`husn/src/ai/model.py`)
Hybrid: `IsolationForest` (anomaly) + `XGBClassifier` (label) + `shap.TreeExplainer` (explanation). `ensure_ready()` is the bootstrap contract — generates `data/synthetic_traffic.csv` if missing and trains+persists `models/*.joblib` if missing. The 17 features in `self.features` are referenced in three places (`model.py`, `data_gen.py`, the SHAP chart in `notify/report.py`) — keep them in sync. **Stale joblibs from an old feature list silently mismatch new data.**

### Active defense (`husn/src/core/response.py`)
`DefenseResponse.block_ip()` is the single chokepoint where everything fans out. It:
1. Checks the whitelist (CIDR-aware).
2. Either logs ("simulated") or shells out to `iptables -A INPUT -s IP -j DROP` (real). Mode flips on `response.real_iptables` in config.
3. Records the block in `_blocked` (exposed as `/blocked`).
4. Optionally schedules an auto-unblock timer.
5. Calls `notify.report.emit()` to persist + email an incident with the SHAP chart inlined.

The AI hands it `attack_type`, `severity`, `confidence` so the email is actionable. The SHAP feature provider is wired in `main.py`'s `lifespan` via `responder.attach_feature_provider(ai.feature_importance)` — that's why the alert email can show the SHAP chart without a circular import.

### Two pseudo-AI features judges care about
Both are state on the `HusnAI` instance, *not* separate subsystems:
- **National Defense Mode** — `predict()` randomly flips ~30% of normal scores to anomaly when active. UI re-themes red.
- **Adaptive Self-Learning** — `knowledge_base_size` increments and `learning_rate` decays inside `predict()`. **Simulated**, not real online training. Don't represent it as real online training to the user.

### Config (`husn/src/config.py`)
Single dotted-path lookup: `cfg.get("smtp.host", default)`. Loaded from (in order) `$HUSN_CONFIG`, `/etc/husn/config.yml`, `config/config.yml`, `config/config.example.yml`. **Secrets never live in the YAML** — keys ending in `_env` are env-var names; the loader resolves them and exposes the value under the same key minus the suffix. Call `cfg.reload()` to pick up edits without restarting.

### Notify subsystem (`husn/src/notify/`)
- `mailer.py` — pure-stdlib SMTP (STARTTLS or SSL), gracefully no-ops if `smtp.enabled: false`. Holds the runtime recipient list (config seed + `/recipients` API mutations).
- `report.py` — builds Markdown + HTML + JSON for every block, renders the SHAP chart as a CID-inlined PNG via headless matplotlib, throttles to one email per source IP per `notify.throttle_seconds`. Reports also persist to disk so nothing is lost when SMTP is down.

### Updater (`husn/src/updater/updater.py`)
Git-based. `check()` does `git fetch` + reports `behind`/`ahead` without mutating. `apply()` refuses to pull onto a dirty tree, refuses non-fast-forward, and re-runs `pip install` only when `requirements.txt` actually changed. `start_scheduler()` is called from `main.py`'s `lifespan`; `_scheduler` is a singleton, idempotent.

### Bilingual UI (`frontend/src/i18n.ts`)
Every UI string has an `en` and `ar` entry. Adding an English-only label visibly breaks Arabic mode. The dashboard auto-applies `dir="rtl"` and flips sidebar/header layout when `lang === 'ar'`.

### Frontend ↔ backend contract
`App.tsx` is a single component holding all state. Two polling loops: fast (2s) for status/monitor/logs, slow (5s) for hardware/ports/processes/blocked/recipients/updater. `API_BASE` reads `import.meta.env.VITE_API_BASE` so production builds can hit `/api` through nginx instead of `localhost:8000`.

### Scapy / raw-socket caveat
`AttackSimulator` and `exploit_demo.py` craft raw packets. They degrade gracefully when raw sockets are unavailable (WSL2 without caps, non-root, etc.) — `_load_scapy()` catches `PermissionError`/`OSError` and prints a warning instead of crashing. Preserve that fallback. On a server, `install.sh` runs `setcap cap_net_raw,cap_net_admin=eip` on the venv python.

## Working norms for this repo

- Priority order (user-stated): **demo flow polish → dashboard quality → CLI quality → novelty features → portability**. When trade-offs arise, favour the higher item.
- The user prizes the contest demo. "Will this wow the judges?" is a legitimate evaluation criterion alongside correctness.
- Comments are welcome — judges read the code — but keep them substantive, not narration.
- Every new UI string needs both `en` and `ar` in `i18n.ts`.
- When changing `HusnAI.features`, retrain models (`cd backend && PYTHONPATH=. ./venv/bin/python -m husn.src.ai.data_gen && python -m husn.src.ai.model`) — stale `.joblib` files mismatch silently.
- New API endpoints: add to `main.py`, then consume in `App.tsx`'s slow-poll tick.
- Real-iptables mode is **off by default** to keep dev safe. Don't flip it on without an explicit user request.
- Mail recipients live in two places: `recipients:` in config (seed) and `_runtime_recipients` in `mailer.py` (added via `/recipients`). The `/recipients` endpoint returns the merged list.
