"""Scheduled summary reports — daily or weekly.

An APScheduler job (started from main.py's lifespan) runs on the
configured cadence, builds a comprehensive report from the learning
store + responder, asks the LLM (DeepSeek) for a natural-language
executive summary, persists the report to /var/log/husn/reports/, and
emails it to the configured recipients.

The schedule is editable at runtime via the dashboard:
  GET  /reports/schedule
  POST /reports/schedule  {frequency: 'daily'|'weekly'|'off', hour, weekday}
  GET  /reports/list
  POST /reports/run-now
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("husn.auto_reports")

_SCHEDULE_FREQS = ("daily", "weekly", "off")
_lock = threading.RLock()
_state: dict[str, Any] | None = None
_path: Path | None = None
_scheduler = None
_job = None


def _resolve_path() -> Path:
    from husn.src import config
    cfg = config.loaded_from()
    if cfg:
        return cfg.parent / "reports.yml"
    return Path("/etc/husn/reports.yml")


def _reports_dir() -> Path:
    from husn.src import config
    p = Path(config.get("paths.reports_dir") or "/var/log/husn/reports")
    p.mkdir(parents=True, exist_ok=True)
    return p


def _load() -> dict[str, Any]:
    global _state, _path
    p = _resolve_path()
    _path = p
    from husn.src import config
    defaults = config.get("reports", {}) or {}
    seed = {
        "frequency": defaults.get("schedule") or "weekly",
        "hour": int(defaults.get("hour", 9)),
        "weekday": int(defaults.get("weekday", 0)),
    }
    if p.exists():
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            seed.update({k: raw.get(k, seed[k]) for k in seed})
        except yaml.YAMLError:
            pass
    if seed["frequency"] not in _SCHEDULE_FREQS:
        seed["frequency"] = "weekly"
    _state = seed
    return _state


def _flush() -> None:
    if _state is None or _path is None:
        return
    tmp = _path.with_suffix(_path.suffix + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(yaml.safe_dump(_state, sort_keys=False), encoding="utf-8")
    os.replace(tmp, _path)


def _ensure() -> dict[str, Any]:
    if _state is None:
        with _lock:
            if _state is None:
                _load()
    return _state  # type: ignore[return-value]


def get_schedule() -> dict[str, Any]:
    s = _ensure()
    return {**s, "frequencies": list(_SCHEDULE_FREQS)}


def set_schedule(frequency: str, hour: int, weekday: int) -> dict[str, Any]:
    if frequency not in _SCHEDULE_FREQS:
        raise ValueError(f"frequency must be one of {_SCHEDULE_FREQS}")
    if not 0 <= int(hour) <= 23:
        raise ValueError("hour must be 0-23")
    if not 0 <= int(weekday) <= 6:
        raise ValueError("weekday must be 0-6")
    s = _ensure()
    with _lock:
        s["frequency"] = frequency
        s["hour"] = int(hour)
        s["weekday"] = int(weekday)
        _flush()
    _reschedule()
    return get_schedule()


# ---------- report building

def _gather_data(window_hours: int) -> dict[str, Any]:
    """Pull stats + raw rows from every subsystem."""
    out: dict[str, Any] = {"window_hours": window_hours}
    cutoff = time.time() - window_hours * 3600

    try:
        from husn.src.learning import store as ls
        events = [e for e in ls.list_events(limit=10000) if (e.get("ts") or 0) > cutoff]
        out["learning_total_events"] = len(events)
        out["learning_confirmed"] = sum(1 for e in events if e.get("feedback") == "confirmed")
        out["learning_false_positive"] = sum(1 for e in events if e.get("feedback") == "false_positive")
        attack_counts = Counter(e.get("attack_type", "?") for e in events)
        out["attack_breakdown"] = attack_counts.most_common(10)
        ip_counts = Counter(e.get("source_ip", "?") for e in events)
        out["top_attackers"] = ip_counts.most_common(10)
        out["latest_accuracy"] = ls.stats().get("last_accuracy")
    except Exception:
        log.exception("[auto_reports] learning gather failed")

    try:
        import main  # type: ignore
        out["currently_blocked"] = len(main.ai.responder.list_blocked())
    except Exception: pass

    try:
        from husn.src.sniffer.sniffer import sniffer
        out["sniffer"] = sniffer.status()
    except Exception: pass

    try:
        from husn.src.honeypot.server import honeypot
        out["honeypot"] = honeypot.status()
    except Exception: pass

    try:
        from husn.src.intel import geoip
        country_counts: Counter = Counter()
        for ip, _count in (out.get("top_attackers") or []):
            cc = (geoip.lookup(ip) or {}).get("country_code")
            if cc:
                country_counts[cc] += 1
        out["top_countries"] = country_counts.most_common(5)
    except Exception: pass

    return out


def _build_report(data: dict[str, Any]) -> dict[str, str]:
    """Generate the human-readable summary via DeepSeek + a fallback HTML doc."""
    from husn.src import llm

    # Compact data block fed to the LLM
    summary_input = json.dumps({
        k: v for k, v in data.items()
        if k in ("window_hours", "learning_total_events", "learning_confirmed",
                 "learning_false_positive", "attack_breakdown", "top_attackers",
                 "top_countries", "currently_blocked", "latest_accuracy")
    }, default=str, ensure_ascii=False)

    sys = (
        "You are Husn's SOC reporter. Write a CONCISE executive summary "
        "(under 250 words, both English and Arabic) of the past period's "
        "cyber-defense activity. Use bullet points. Highlight: total events, "
        "top attack classes, top source IPs/countries, AI accuracy if available, "
        "and one recommendation. Don't invent data — only use what's in the JSON."
    )
    msg = f"Here is the raw activity data for the last {data.get('window_hours')} hours:\n\n{summary_input}"

    res = llm.complete(system=sys, messages=[{"role": "user", "content": msg}])
    narrative = res.get("reply") if res.get("ok") else (
        f"(LLM summary unavailable — {res.get('error', '')})"
    )
    return {"narrative": narrative, "raw_input": summary_input}


def _render_html(window_label: str, data: dict[str, Any], narrative: str) -> str:
    org = ""
    try:
        from husn.src import config
        org = config.get("organization.name") or ""
    except Exception: pass

    rows = lambda lst: "".join(
        f'<tr><td style="padding:6px 12px;border-top:1px solid #1f2a37">{a}</td>'
        f'<td style="padding:6px 12px;border-top:1px solid #1f2a37;text-align:right">{b}</td></tr>'
        for a, b in (lst or [])[:10]
    )
    return f"""<!doctype html><html><body style="margin:0;background:#0a0e14;font-family:Helvetica,Arial,sans-serif;color:#e6f1ff">
<table width="720" align="center" cellpadding="0" cellspacing="0" style="background:#0e1520;border:1px solid #1f2a37;border-radius:12px;margin:32px auto">
<tr><td style="padding:24px 32px;background:linear-gradient(90deg,#0e1520,#102233);border-bottom:1px solid #1f2a37">
  <div style="font-size:11px;letter-spacing:0.2em;color:#00ff9d;text-transform:uppercase">{org or "Husn Defense"}</div>
  <div style="font-size:22px;font-weight:600;margin-top:4px">حصن — Periodic Cyber-Defense Report</div>
  <div style="font-size:13px;color:#9aa6b2;margin-top:4px">{window_label}</div>
</td></tr>
<tr><td style="padding:24px 32px;font-size:14px;line-height:1.6">
  <pre style="white-space:pre-wrap;font-family:inherit;color:#e6f1ff;margin:0">{narrative}</pre>
</td></tr>
<tr><td style="padding:0 32px 24px">
  <h3 style="color:#00ff9d;font-size:13px;text-transform:uppercase;letter-spacing:.2em">Top attack classes</h3>
  <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px"><tbody>{rows(data.get("attack_breakdown"))}</tbody></table>

  <h3 style="color:#00ff9d;font-size:13px;text-transform:uppercase;letter-spacing:.2em;margin-top:18px">Top source IPs</h3>
  <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;font-family:monospace"><tbody>{rows(data.get("top_attackers"))}</tbody></table>

  <h3 style="color:#00ff9d;font-size:13px;text-transform:uppercase;letter-spacing:.2em;margin-top:18px">Top countries</h3>
  <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px"><tbody>{rows(data.get("top_countries"))}</tbody></table>
</td></tr>
<tr><td style="padding:18px 32px;border-top:1px solid #1f2a37;font-size:11px;color:#6b7785">
  Generated {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())} · Currently blocked IPs: {data.get("currently_blocked", 0)} ·
  AI accuracy: {data.get("latest_accuracy", "—")}
</td></tr>
</table></body></html>"""


def run_now(triggered_by: str = "manual") -> dict[str, Any]:
    s = _ensure()
    window = 24 if s["frequency"] == "daily" else 24 * 7
    label = "Last 24 hours" if window == 24 else "Last 7 days"
    data = _gather_data(window)
    rep = _build_report(data)
    html = _render_html(label, data, rep["narrative"])

    out_dir = _reports_dir()
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    base = out_dir / f"summary-{ts}-{s['frequency']}"
    base.with_suffix(".html").write_text(html, encoding="utf-8")
    base.with_suffix(".md").write_text(
        f"# Husn — {label}\n\n{rep['narrative']}\n\n---\n```json\n{rep['raw_input']}\n```\n",
        encoding="utf-8")

    # Email it
    email_status = None
    try:
        from husn.src.notify import mailer
        if mailer.is_enabled():
            send = mailer.send(
                subject=f"[Husn] Periodic report · {label}",
                html_body=html,
                text_body=rep["narrative"],
                attachments={f"{base.name}.md": Path(base.with_suffix('.md')).read_bytes()},
            )
            email_status = {"ok": send.ok, "detail": send.detail, "to": send.recipients}
    except Exception as exc:
        email_status = {"ok": False, "detail": str(exc), "to": []}

    log.info("[auto_reports] %s report generated (%s) — emailed=%s",
             s["frequency"], base.name, bool(email_status and email_status.get("ok")))

    return {
        "frequency": s["frequency"], "window_label": label,
        "report_path": str(base.with_suffix(".html")),
        "triggered_by": triggered_by,
        "email": email_status,
        "narrative_preview": rep["narrative"][:280],
    }


def list_reports(limit: int = 30) -> list[dict[str, Any]]:
    out_dir = _reports_dir()
    out: list[dict[str, Any]] = []
    for p in sorted(out_dir.glob("summary-*.html"), reverse=True)[:limit]:
        out.append({
            "name": p.name,
            "size_bytes": p.stat().st_size,
            "mtime": p.stat().st_mtime,
            "url": f"/reports/{p.name}",
        })
    return out


def read_report(name: str) -> str | None:
    safe = (name or "").replace("/", "").replace("..", "")
    p = _reports_dir() / safe
    if not p.exists() or not p.is_file():
        return None
    return p.read_text(encoding="utf-8")


# ---------- scheduler

def _reschedule() -> None:
    global _job
    if _scheduler is None:
        return
    if _job is not None:
        try: _job.remove()
        except Exception: pass
        _job = None
    s = _ensure()
    if s["frequency"] == "off":
        log.info("[auto_reports] schedule off — no job")
        return
    from apscheduler.triggers.cron import CronTrigger
    if s["frequency"] == "daily":
        trig = CronTrigger(hour=s["hour"], minute=0)
    else:
        trig = CronTrigger(day_of_week=s["weekday"], hour=s["hour"], minute=0)
    _job = _scheduler.add_job(lambda: run_now("scheduled"), trig, id="husn-auto-report",
                              replace_existing=True)
    log.info("[auto_reports] scheduled %s reports at hour=%d weekday=%d",
             s["frequency"], s["hour"], s["weekday"])


def start_scheduler() -> None:
    global _scheduler
    from husn.src import config
    if not (config.get("reports", {}) or {}).get("enabled", True):
        return
    if _scheduler is not None:
        return
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        log.warning("[auto_reports] apscheduler not installed; reports disabled.")
        return
    _scheduler = BackgroundScheduler(daemon=True, timezone="UTC")
    _scheduler.start()
    _reschedule()


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        try: _scheduler.shutdown(wait=False)
        except Exception: pass
        _scheduler = None
