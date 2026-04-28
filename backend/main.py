"""Husn FastAPI backend.

Routes are grouped by purpose:
  /auth/*                                     — login + user management
  /status, /monitor, /logs, /toggle-defense   — legacy demo state
  /scan, /simulate, /explain                  — AI-driven actions
  /system/*                                   — host telemetry
  /blocked*                                   — active-defense registry
  /recipients*                                — runtime mail recipients
  /updates/*                                  — self-update channel
  /test-alert                                 — verify SMTP wiring

Auth model:
  * /auth/login is open.
  * Read-only routes (every GET) require any logged-in user.
  * Write routes (POST/DELETE) require admin role.
"""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import Any

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from husn.src import config as cfg
from husn.src.ai.model import DEFAULT_DATA_PATH, HusnAI
from husn.src.auth import tokens, users, ratelimit as auth_ratelimit
from husn.src.auth.deps import require_admin, require_user
from husn.src.core.simulator import AttackSimulator
from husn.src.chat import chatbot
from husn.src.core import lists as defense_lists
from husn.src.honeypot.server import honeypot
from husn.src.intel import geoip, reputation
from husn.src.learning import store as learning_store, trainer as learning_trainer
from husn.src.notify import mailer, report, settings as notify_settings, auto_reports
from husn.src.sniffer.sniffer import sniffer
from husn.src.system import hardware, network, processes, scanner
from husn.src.system import traffic
from husn.src.updater import updater

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
log = logging.getLogger("husn.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg.reload()
    log.info("Husn config loaded from %s", cfg.loaded_from())
    # Force the user store to seed if it's empty (first run).
    users.reload()
    seeded = users.list_users()
    log.info("Husn auth — %d user(s) loaded from %s", len(seeded), users.store_path())
    ai.ensure_ready()
    ai.responder.attach_feature_provider(ai.feature_importance)
    auth_ratelimit.attach(responder_provider=lambda: ai.responder, log_provider=_log)
    # Seed the real learning telemetry from the SQLite store.
    try:
        s = learning_store.stats()
        if s.get("last_total_samples"):
            ai.knowledge_base_size = int(s["last_total_samples"])
        if s.get("last_accuracy") is not None:
            ai.learning_rate = float(s["last_accuracy"])
    except Exception:
        log.exception("could not seed learning telemetry")
    traffic.sampler.start()
    sniffer.start(ai_provider=lambda: ai)
    honeypot.start(responder_provider=lambda: ai.responder)
    updater.start_scheduler()
    auto_reports.start_scheduler()
    yield
    auto_reports.stop_scheduler()
    updater.stop_scheduler()
    honeypot.stop()
    sniffer.stop()
    traffic.sampler.stop()


app = FastAPI(title="Husn API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ai = HusnAI()
logs: list[str] = []


def _log(msg: str) -> None:
    logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
    if len(logs) > 500:
        del logs[: len(logs) - 500]


# ---------------------------------------------------------------- request bodies

class SimulationRequest(BaseModel):
    target_ip: str
    attack_type: str


class ScanRequest(BaseModel):
    target: str


class TargetRequest(BaseModel):
    target: str


class RecipientRequest(BaseModel):
    email: str


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str  # "admin" | "employee"


class SetPasswordRequest(BaseModel):
    password: str


class SetRoleRequest(BaseModel):
    role: str


# ---------------------------------------------------------------- auth

@app.post("/auth/login")
def auth_login(req: LoginRequest, request: Request):
    """Hardened login: per-IP rate limit + per-user lockout + auto-block on
    sustained brute force. Husn defends ITSELF using its own pipeline."""
    src_ip = (request.client.host if request.client else "unknown") or "unknown"

    # 1. IP-level rate limit
    ok, retry = auth_ratelimit.check_ip_allowed(src_ip)
    if not ok:
        _log(f"AUTH: rate-limited login from {src_ip} (retry in {retry}s)")
        raise HTTPException(
            status_code=429,
            detail=f"too many attempts — retry in {retry} seconds",
            headers={"Retry-After": str(retry)},
        )

    # 2. Account-level lockout
    ok, retry = auth_ratelimit.check_user_allowed(req.username)
    if not ok:
        _log(f"AUTH: locked-account login attempt for {req.username!r} from {src_ip}")
        raise HTTPException(
            status_code=423,
            detail=f"account temporarily locked — retry in {retry} seconds",
            headers={"Retry-After": str(retry)},
        )

    # 3. Real password check
    user = users.authenticate(req.username, req.password)
    if user is None:
        result = auth_ratelimit.record_failure(req.username, src_ip)
        _log(f"AUTH: failed login for {req.username!r} from {src_ip} "
             f"(ip-fail={result['ip_failures']} user-fail={result['user_failures']})")
        # Generic message — don't disclose which side was wrong.
        raise HTTPException(status_code=401, detail="invalid username or password")

    # 4. Success path
    auth_ratelimit.record_success(req.username, src_ip)
    token = tokens.issue(user["username"], user["role"])
    _log(f"AUTH: {user['username']} ({user['role']}) logged in from {src_ip}")
    return {
        "token": token,
        "user": {"username": user["username"], "role": user["role"]},
        "ttl_seconds": int(cfg.get("auth.token_ttl_seconds", 28800)),
    }


@app.get("/auth/security")
def auth_security(_: dict = Depends(require_admin)):
    """Live login-security state: rate-limited IPs, locked accounts."""
    return auth_ratelimit.status()


@app.get("/auth/me")
def auth_me(user: dict = Depends(require_user)):
    return user


@app.get("/auth/users")
def auth_users(_: dict = Depends(require_admin)):
    return {"users": users.list_users(), "roles": list(users.roles())}


@app.post("/auth/users")
def auth_create_user(req: CreateUserRequest, actor: dict = Depends(require_admin)):
    try:
        created = users.create(req.username, req.password, req.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _log(f"AUTH: {actor['username']} created user {created['username']} ({created['role']})")
    return created


@app.delete("/auth/users/{username}")
def auth_delete_user(username: str, actor: dict = Depends(require_admin)):
    if username.lower() == actor["username"].lower():
        raise HTTPException(status_code=400, detail="you cannot delete yourself")
    try:
        removed = users.delete(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not removed:
        raise HTTPException(status_code=404, detail="user not found")
    _log(f"AUTH: {actor['username']} deleted user {username}")
    return {"ok": True}


@app.post("/auth/users/{username}/password")
def auth_set_password(username: str, req: SetPasswordRequest, actor: dict = Depends(require_admin)):
    try:
        ok = users.set_password(username, req.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=404, detail="user not found")
    _log(f"AUTH: {actor['username']} reset password for {username}")
    return {"ok": True}


@app.get("/auth/audit")
def auth_audit(_: dict = Depends(require_admin), limit: int = 50):
    """Filtered view of the in-memory log — every AUTH event in chronological order."""
    rows = [l for l in logs if "AUTH:" in l]
    return {"events": rows[-limit:][::-1], "total": len(rows)}


@app.post("/auth/users/{username}/role")
def auth_set_role(username: str, req: SetRoleRequest, actor: dict = Depends(require_admin)):
    try:
        ok = users.set_role(username, req.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=404, detail="user not found")
    _log(f"AUTH: {actor['username']} changed {username} → {req.role}")
    return {"ok": True}


# ---------------------------------------------------------------- legacy demo

@app.get("/status")
def get_status(_: dict = Depends(require_user)) -> dict[str, Any]:
    return {
        "ai_engine": "online",
        "network_monitor": "active",
        "shield": "active",
        "threat_level": "low" if ai.defense_mode == "Standard" else "critical",
        "defense_mode": ai.defense_mode,
        "self_learning": {
            "rate": f"{ai.learning_rate:.4f}",
            "knowledge_base": ai.knowledge_base_size,
        },
        "smtp_enabled": mailer.is_enabled(),
        "real_iptables": bool(cfg.get("response.real_iptables", False)),
        "domain": cfg.get("domain", ""),
        "organization": cfg.get("organization.name", ""),
    }


@app.post("/toggle-defense")
def toggle_defense(actor: dict = Depends(require_admin)) -> dict[str, str]:
    ai.defense_mode = "National" if ai.defense_mode == "Standard" else "Standard"
    _log(f"SYSTEM: {actor['username']} switched defense mode to {ai.defense_mode}")
    return {"mode": ai.defense_mode}


@app.get("/monitor")
def get_monitoring_data(_: dict = Depends(require_user)) -> dict[str, Any]:
    """Real-time host network telemetry. No random numbers — every value here
    is a true measurement from the running machine."""
    latest = traffic.sampler.latest()
    blocked_now = len(ai.responder.list_blocked())
    blocks_total = sum(1 for line in logs if "ACTIVE DEFENSE" in line or "Blocking" in line)
    return {
        "timestamp": time.time(),
        # Backwards-compatible field names so the existing chart still binds,
        # but the values are now actual bytes/sec from psutil.
        "incoming": latest["bytes_in_per_s"],
        "outgoing": latest["bytes_out_per_s"],
        "malicious": blocked_now,
        # Newer, clearer names for the redesigned UI.
        "incoming_bps": latest["bytes_in_per_s"],
        "outgoing_bps": latest["bytes_out_per_s"],
        "incoming_pps": latest["packets_in_per_s"],
        "outgoing_pps": latest["packets_out_per_s"],
        "blocked_now": blocked_now,
        "blocks_total": blocks_total,
        "uptime_seconds": int(time.time() - hardware.os_info()["boot_time"]),
        "threats_blocked": blocks_total,
        "defense_mode": ai.defense_mode,
    }


@app.post("/scan")
def run_ai_scan(req: ScanRequest, actor: dict = Depends(require_admin)):
    _log(f"SCAN STARTED: {actor['username']} → {req.target}")
    sample_df = pd.read_csv(DEFAULT_DATA_PATH).sample(5)
    X = sample_df[ai.features]
    return ai.predict(X)


@app.post("/simulate")
def trigger_simulation(req: SimulationRequest, actor: dict = Depends(require_admin)):
    sim = AttackSimulator(req.target_ip)
    if "DDoS" in req.attack_type:
        sim.ddos_simulation(count=20)
    elif "Port" in req.attack_type:
        sim.port_scan_simulation()
    elif "RCE" in req.attack_type:
        sim.rce_exploit_simulation()
    else:
        sim.brute_force_simulation()

    sample_df = pd.read_csv(DEFAULT_DATA_PATH)
    target_label = "DDoS" if "DDoS" in req.attack_type else (
        "PortScan" if "Port" in req.attack_type else (
            "Brute Force" if "Brute" in req.attack_type else "Infiltration"))
    matching = sample_df[sample_df["label"] == target_label].head(3)
    if not matching.empty:
        ai.predict(matching[ai.features], source_ips=[req.target_ip] * len(matching))

    _log(f"SIMULATION: {actor['username']} → {req.attack_type} against {req.target_ip}")
    return {"status": "success", "message": f"Simulation of {req.attack_type} completed."}


@app.get("/logs")
def get_logs(_: dict = Depends(require_user)):
    return logs[-30:]


@app.get("/explain")
def get_explanation(_: dict = Depends(require_user)):
    feature_importance = ai.feature_importance()
    feature_importance.sort(key=lambda x: abs(x["value"]), reverse=True)
    return {"features": feature_importance[:10], "base_value": 0.5}


# ---------------------------------------------------------------- system telemetry

@app.get("/system/hardware")
def system_hardware(_: dict = Depends(require_user)):
    return hardware.snapshot()


@app.get("/system/ports")
def system_ports(_: dict = Depends(require_user)):
    return network.listening_ports()


@app.get("/system/processes")
def system_processes(suspicious_only: bool = False, limit: int = 40,
                     _: dict = Depends(require_user)):
    return processes.suspicious_only() if suspicious_only else processes.list_processes(limit)


@app.get("/system/network")
def system_network(_: dict = Depends(require_user)):
    return {
        "listening": network.listening_ports(),
        "established": network.established_connections(),
        "services": network.services(),
    }


@app.get("/system/connections")
def system_connections(_: dict = Depends(require_user)):
    """Real established connections + per-remote-IP and per-process aggregates,
    enriched with GeoIP for every unique remote (cached)."""
    data = network.connections_grouped()
    for row in data.get("by_remote", []):
        row["geo"] = geoip.lookup(row["remote_ip"])
    return data


@app.get("/system/traffic")
def system_traffic(_: dict = Depends(require_user)):
    """120-second sliding window of real bytes/sec + packets/sec per interface."""
    return traffic.sampler.snapshot()


@app.get("/sniffer/status")
def sniffer_status(_: dict = Depends(require_user)):
    """Live sniffer telemetry — packet count, active flows, predictions, blocks."""
    return sniffer.status()


@app.get("/honeypot/status")
def honeypot_status(_: dict = Depends(require_user)):
    """Honeypot listener state + recent intrusion attempts."""
    return honeypot.status()


@app.post("/system/scan")
def system_scan(req: TargetRequest, _: dict = Depends(require_admin)):
    return scanner.scan(req.target)


# ---------------------------------------------------------------- defense

@app.get("/blocked")
def list_blocked(_: dict = Depends(require_user)):
    from husn.src.notify.explanation import explain as nl_explain
    fi = ai.feature_importance()
    rows = ai.responder.list_blocked()
    for r in rows:
        r["geo"] = geoip.lookup(r["ip"])
        r["reputation"] = reputation.lookup(r["ip"])
        r["explanation"] = nl_explain(
            r.get("attack_type", ""), float(r.get("confidence", 0) or 0), fi, r["ip"],
        )
    return rows


@app.get("/intel/{ip}")
def intel_lookup(ip: str, _: dict = Depends(require_user)):
    return {"ip": ip, "geo": geoip.lookup(ip), "reputation": reputation.lookup(ip)}


@app.get("/investigate/{ip}")
def investigate(ip: str, _: dict = Depends(require_user)):
    """One-click investigation: aggregate everything Husn knows about an IP
    + ask the LLM for a brief situational analysis with recommended action.
    Used by the Defense tab's 'Investigate' button."""
    from husn.src.notify.explanation import explain as nl_explain
    from husn.src import llm as _llm

    geo = geoip.lookup(ip)
    rep = reputation.lookup(ip)

    # Pull all historical block events for this IP from the learning store
    events: list[dict[str, Any]] = []
    try:
        events = [e for e in learning_store.list_events(limit=500) if e.get("source_ip") == ip]
    except Exception:
        pass

    # Currently blocked? Get its row + decorate with NL explanation
    blocked_row = None
    for r in ai.responder.list_blocked():
        if r.get("ip") == ip:
            blocked_row = dict(r)
            blocked_row["explanation"] = nl_explain(
                r.get("attack_type", ""), float(r.get("confidence", 0) or 0),
                ai.feature_importance(), ip,
            )
            break

    # Honeypot probes from this IP (if any)
    honeypot_hits: list[dict[str, Any]] = []
    try:
        for ev in honeypot.status().get("events", []) or []:
            if ev.get("src_ip") == ip:
                honeypot_hits.append(ev)
    except Exception:
        pass

    # Whitelist / blacklist membership
    listed = {
        "in_ip_whitelist": defense_lists.is_ip_allowed(ip),
        "in_ip_blacklist": defense_lists.is_ip_denied(ip),
        "in_country_whitelist": defense_lists.is_country_allowed(geo.get("country_code")),
        "in_country_blacklist": defense_lists.is_country_denied(geo.get("country_code")),
    }

    # Ask the LLM for a SOC analyst summary + recommendation
    analysis = None
    if _llm.is_configured():
        compact = {
            "ip": ip,
            "geo": {k: geo.get(k) for k in ("country", "country_code", "city", "asn")},
            "reputation": rep,
            "currently_blocked": bool(blocked_row),
            "block_event_count": len(events),
            "attack_classes_seen": list({e.get("attack_type") for e in events}),
            "honeypot_hits": len(honeypot_hits),
            "list_status": listed,
        }
        sys = (
            "You are Husn's SOC analyst. Given the JSON about a single IP, write 4-6 "
            "concise bullet points: (1) what this IP is and where it's from, "
            "(2) what it's done against us, (3) reputation read, "
            "(4) RECOMMENDED ACTION — one of: 'Whitelist', 'Permanent blacklist', "
            "'Keep current block', 'No action needed'. "
            "Bilingual: English first, Arabic second. Markdown."
        )
        msg = f"Investigate this IP:\n\n```json\n{compact}\n```"
        r = _llm.complete(system=sys, messages=[{"role": "user", "content": msg}],
                          temperature_override=0.2, max_tokens_override=600)
        analysis = r.get("reply") if r.get("ok") else f"(LLM unavailable — {r.get('error','?')})"

    return {
        "ip": ip,
        "geo": geo,
        "reputation": rep,
        "currently_blocked": blocked_row,
        "block_event_count": len(events),
        "block_events": events[:20],
        "honeypot_hits": honeypot_hits[:20],
        "list_status": listed,
        "analysis": analysis,
    }


# ---------------------------------------------------------------- defense lists

class ListEntryRequest(BaseModel):
    value: str


@app.get("/defense/lists")
def defense_get_lists(_: dict = Depends(require_user)):
    """All four runtime lists: ip_whitelist, ip_blacklist, country_whitelist, country_blacklist.
    Each country code is enriched with its flag emoji for the UI."""
    state = defense_lists.all_lists()
    cc_to_flag = lambda cc: (
        chr(0x1F1E6 + ord(cc[0]) - ord("A")) + chr(0x1F1E6 + ord(cc[1]) - ord("A"))
        if len(cc) == 2 else "🏳️"
    )
    return {
        "ip_whitelist": state["ip_whitelist"],
        "ip_blacklist": state["ip_blacklist"],
        "country_whitelist": [{"code": c, "flag": cc_to_flag(c)} for c in state["country_whitelist"]],
        "country_blacklist": [{"code": c, "flag": cc_to_flag(c)} for c in state["country_blacklist"]],
    }


@app.post("/defense/lists/{kind}")
def defense_list_add(kind: str, req: ListEntryRequest, actor: dict = Depends(require_admin)):
    if kind not in defense_lists.VALID_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {defense_lists.VALID_KINDS}")
    try:
        added = defense_lists.add(kind, req.value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _log(f"DEFENSE: {actor['username']} added {req.value!r} to {kind}")
    return {"ok": True, "added": added, "kind": kind, "value": req.value}


@app.delete("/defense/lists/{kind}/{value:path}")
def defense_list_remove(kind: str, value: str, actor: dict = Depends(require_admin)):
    if kind not in defense_lists.VALID_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {defense_lists.VALID_KINDS}")
    try:
        removed = defense_lists.remove(kind, value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not removed:
        raise HTTPException(status_code=404, detail="entry not in list")
    _log(f"DEFENSE: {actor['username']} removed {value!r} from {kind}")
    return {"ok": True, "removed": True, "kind": kind, "value": value}


@app.post("/blocked/{ip}/unblock")
def unblock(ip: str, actor: dict = Depends(require_admin)):
    result = ai.responder.unblock_ip(ip)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error", "not blocked"))
    _log(f"DEFENSE: {actor['username']} manually unblocked {ip}")
    return result


# ---------------------------------------------------------------- recipients

@app.get("/recipients")
def list_recipients(_: dict = Depends(require_user)):
    return {"recipients": mailer.recipients(), "smtp_enabled": mailer.is_enabled()}


@app.post("/recipients")
def add_recipient(req: RecipientRequest, _: dict = Depends(require_admin)):
    if not req.email or "@" not in req.email:
        raise HTTPException(status_code=400, detail="invalid email")
    added = mailer.add_recipient(req.email.strip())
    return {"ok": added, "recipients": mailer.recipients()}


@app.delete("/recipients/{email}")
def remove_recipient(email: str, _: dict = Depends(require_admin)):
    removed = mailer.remove_recipient(email)
    return {"ok": removed, "recipients": mailer.recipients()}


@app.post("/test-alert")
def test_alert(_: dict = Depends(require_admin)):
    return report.send_test_email()


# ---------------------------------------------------------------- notify settings

class NotifySeverityRequest(BaseModel):
    min_severity: str   # low | medium | high | critical


class NotifyPauseRequest(BaseModel):
    seconds: int        # 0 = resume, -1 = forever, N>0 = pause for N s


@app.get("/notify/settings")
def notify_settings_get(_: dict = Depends(require_user)):
    return notify_settings.get()


@app.post("/notify/settings/severity")
def notify_settings_severity(req: NotifySeverityRequest, actor: dict = Depends(require_admin)):
    try:
        v = notify_settings.set_min_severity(req.min_severity)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _log(f"NOTIFY: {actor['username']} set min_severity={v}")
    return notify_settings.get()


@app.post("/notify/settings/pause")
def notify_settings_pause(req: NotifyPauseRequest, actor: dict = Depends(require_admin)):
    until = notify_settings.pause(req.seconds)
    state = "resumed" if req.seconds == 0 else "paused forever" if req.seconds < 0 else f"paused for {req.seconds}s"
    _log(f"NOTIFY: {actor['username']} {state}")
    return notify_settings.get()


# ---------------------------------------------------------------- SOC chatbot

class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"


@app.get("/chat/status")
def chat_status(_: dict = Depends(require_user)):
    return {"configured": chatbot.is_configured(), "model": (cfg.get("llm.model") or "deepseek-chat")}


@app.post("/chat/send")
def chat_send(req: ChatRequest, actor: dict = Depends(require_user)):
    sid = f"{actor['username']}::{req.session_id}"
    return chatbot.chat(sid, req.message)


@app.post("/chat/reset")
def chat_reset(req: ChatRequest, actor: dict = Depends(require_user)):
    sid = f"{actor['username']}::{req.session_id}"
    chatbot.reset_session(sid)
    return {"ok": True}


# ---------------------------------------------------------------- automated reports

class ReportScheduleRequest(BaseModel):
    frequency: str   # daily | weekly | off
    hour: int = 9
    weekday: int = 0


@app.get("/reports/schedule")
def reports_schedule_get(_: dict = Depends(require_user)):
    return auto_reports.get_schedule()


@app.post("/reports/schedule")
def reports_schedule_set(req: ReportScheduleRequest, actor: dict = Depends(require_admin)):
    try:
        s = auto_reports.set_schedule(req.frequency, req.hour, req.weekday)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _log(f"REPORTS: {actor['username']} set schedule {s}")
    return s


@app.get("/reports/list")
def reports_list(_: dict = Depends(require_user)):
    return auto_reports.list_reports()


@app.post("/reports/run-now")
def reports_run_now(actor: dict = Depends(require_admin)):
    _log(f"REPORTS: {actor['username']} triggered manual report")
    return auto_reports.run_now(triggered_by=actor["username"])


@app.get("/reports/{name}")
def reports_download(name: str, _: dict = Depends(require_user)):
    from fastapi.responses import HTMLResponse
    body = auto_reports.read_report(name)
    if body is None:
        raise HTTPException(status_code=404, detail="report not found")
    return HTMLResponse(content=body)


# ---------------------------------------------------------------- updater

@app.get("/updates/status")
def updates_status(_: dict = Depends(require_user)):
    return updater.status()


@app.post("/updates/check")
def updates_check(_: dict = Depends(require_admin)):
    return updater.check()


@app.post("/updates/apply")
def updates_apply(_: dict = Depends(require_admin)):
    return updater.apply()


# ---------------------------------------------------------------- web terminal

class CliRunRequest(BaseModel):
    command: str
    args: str = ""


class LearningFeedbackRequest(BaseModel):
    feedback: str   # "confirmed" | "false_positive" | "unconfirmed"


# ---------------------------------------------------------------- learning loop

@app.get("/learning/stats")
def learning_stats(_: dict = Depends(require_user)):
    """Real adaptive-learning telemetry — replaces the old simulated counters."""
    s = learning_store.stats()
    s["current_kb_size"] = ai.knowledge_base_size
    s["current_accuracy"] = ai.learning_rate
    s["features"] = ai.features
    return s


@app.get("/learning/events")
def learning_events(limit: int = 50, _: dict = Depends(require_user)):
    return learning_store.list_events(limit=limit)


@app.post("/learning/feedback/{event_id}")
def learning_feedback(event_id: int, req: LearningFeedbackRequest,
                      actor: dict = Depends(require_admin)):
    try:
        ok = learning_store.set_feedback(event_id, req.feedback, actor["username"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="event not found")
    _log(f"LEARNING: {actor['username']} marked event #{event_id} as {req.feedback}")
    return {"ok": True}


@app.post("/learning/retrain")
def learning_retrain(actor: dict = Depends(require_admin)):
    """Trigger a fresh retrain right now using base CSV + confirmed events."""
    try:
        result = learning_trainer.retrain(ai, source=f"manual:{actor['username']}")
    except Exception as exc:
        log.exception("retrain failed")
        raise HTTPException(status_code=500, detail=f"retrain failed: {exc}")
    _log(f"LEARNING: {actor['username']} retrained — samples={result['total_samples']}, acc={result['accuracy']:.4f}")
    return result


# Whitelist of allowed CLI commands. Each entry maps the user-facing name
# to a (callable, argspec) pair. The callable runs in-process — no shell out,
# no eval, no subprocess. All output is captured into a Rich Console with
# `record=True` and returned as plain text + ANSI-coloured text + HTML.
def _build_cli_dispatch() -> dict[str, Any]:
    from husn.src.system import hardware as _hw, network as _net, processes as _procs, scanner as _scan
    from rich.console import Console
    from rich.table import Table
    from rich import box

    def _new_console() -> Console:
        return Console(record=True, width=110, color_system="truecolor", force_terminal=True)

    def _sysinfo(_args: str) -> Console:
        c = _new_console()
        snap = _hw.snapshot()
        os_, cpu, mem = snap["os"], snap["cpu"], snap["memory"]
        c.print(f"[bold green]HOST[/bold green]      {os_['hostname']} ({os_['fqdn']})")
        c.print(f"[bold green]OS[/bold green]        {os_['system']} {os_['release']}")
        c.print(f"[bold green]CPU[/bold green]       {cpu['model']} · {cpu['physical_cores']}c/{cpu['logical_cores']}t · {cpu['usage_percent']}%")
        c.print(f"[bold green]RAM[/bold green]       {mem['used_gb']} / {mem['total_gb']} GB ({mem['percent']}%)")
        return c

    def _ports(_args: str) -> Console:
        c = _new_console()
        rows = _net.listening_ports()
        t = Table(title=f"Listening ({len(rows)})", box=box.SIMPLE_HEAD)
        for h in ("Port", "Proto", "Service", "PID", "Process"):
            t.add_column(h)
        for r in rows:
            t.add_row(str(r["port"]), r["protocol"], r["service"], str(r["pid"] or "—"), r["process"] or "—")
        c.print(t)
        return c

    def _services(_args: str) -> Console:
        c = _new_console()
        t = Table(title="Services", box=box.SIMPLE_HEAD)
        for h in ("Process", "PID", "Ports"):
            t.add_column(h)
        for s in _net.services():
            t.add_row(s["process"], str(s["pid"] or "—"), ", ".join(map(str, s["ports"])))
        c.print(t)
        return c

    def _procs_cmd(args: str) -> Console:
        c = _new_console()
        sus = "--suspicious" in args or "-s" in args
        rows = _procs.suspicious_only() if sus else _procs.list_processes(40)
        t = Table(title=f"Processes ({len(rows)})", box=box.SIMPLE_HEAD)
        for h in ("PID", "User", "Name", "CPU%", "Mem%", "Conn", "Flag"):
            t.add_column(h)
        for r in rows:
            flag = f"[red]⚠ {r['reason']}[/red]" if r["suspicious"] else ""
            t.add_row(str(r["pid"]), r["user"], r["name"], str(r["cpu_percent"]),
                      str(r["memory_percent"]), str(r["connections"]) if r["connections"] >= 0 else "—", flag)
        c.print(t)
        return c

    def _scan_cmd(args: str) -> Console:
        c = _new_console()
        target = (args or "").strip().split()[0] if args.strip() else ""
        if not target:
            c.print("[red]Usage: scan <host-or-ip>[/red]")
            return c
        result = _scan.scan(target)
        if result.get("error"):
            c.print(f"[red]✗ {result['error']}[/red]")
            return c
        c.print(f"Resolved: [cyan]{result['resolved_ip']}[/cyan]   Engine: [magenta]{result['engine']}[/magenta]   Took: {result['duration_seconds']}s")
        t = Table(box=box.SIMPLE_HEAD)
        for h in ("Port", "Service", "State", "Version"):
            t.add_column(h)
        for r in result["open_ports"]:
            t.add_row(str(r["port"]), r["service"], r["state"], r.get("version", ""))
        c.print(t)
        return c

    def _blocked(_args: str) -> Console:
        c = _new_console()
        rows = ai.responder.list_blocked()
        if not rows:
            c.print("[green]✓ No IPs are currently blocked.[/green]")
            return c
        t = Table(title=f"Blocked ({len(rows)})", box=box.SIMPLE_HEAD)
        for h in ("IP", "Attack", "Severity", "Confidence", "When"):
            t.add_column(h)
        for r in rows:
            when = time.strftime("%H:%M:%S", time.localtime(r["blocked_at"]))
            t.add_row(r["ip"], r["attack_type"], r["severity"], f"{r['confidence']:.1%}", when)
        c.print(t)
        return c

    def _status(_args: str) -> Console:
        c = _new_console()
        c.print(f"AI engine     : [green]ONLINE[/green]")
        c.print(f"SMTP          : [{'green' if mailer.is_enabled() else 'yellow'}]{'ENABLED' if mailer.is_enabled() else 'DISABLED'}[/]")
        c.print(f"iptables mode : [{'red' if cfg.get('response.real_iptables') else 'yellow'}]{'REAL' if cfg.get('response.real_iptables') else 'SIMULATED'}[/]")
        c.print(f"Defense mode  : [bold]{ai.defense_mode}[/bold]")
        c.print(f"Blocked IPs   : {len(ai.responder.list_blocked())}")
        c.print(f"Recipients    : {len(mailer.recipients())}")
        c.print(f"Sniffer       : {sniffer.status()['running']} ({sniffer.status()['active_flows']} flows)")
        c.print(f"Honeypot      : {honeypot.status()['running']} on {honeypot.status()['listening_ports']}")
        return c

    def _check(_args: str) -> Console:
        c = _new_console()
        r = updater.check()
        col = "yellow" if r.get("available") else "green"
        c.print(f"[{col}]{r.get('message', '?')}[/{col}]")
        c.print(f"current: {r.get('current_commit', '—')}   remote: {r.get('remote_commit', '—')}   behind: {r.get('behind', 0)}")
        return c

    return {
        "sysinfo":  _sysinfo,
        "ports":    _ports,
        "services": _services,
        "procs":    _procs_cmd,
        "scan":     _scan_cmd,
        "blocked":  _blocked,
        "status":   _status,
        "check":    _check,
    }


_CLI_DISPATCH: dict[str, Any] | None = None


def _cli_dispatch():
    global _CLI_DISPATCH
    if _CLI_DISPATCH is None:
        _CLI_DISPATCH = _build_cli_dispatch()
    return _CLI_DISPATCH


@app.get("/cli/commands")
def cli_commands(_: dict = Depends(require_user)):
    """Whitelist that the dashboard's Terminal tab populates from."""
    return {"commands": sorted(_cli_dispatch().keys())}


@app.post("/cli/run")
def cli_run(req: CliRunRequest, actor: dict = Depends(require_admin)):
    """Run a whitelisted CLI command in-process. Captures the Rich-rendered
    output and returns it as plain text + ANSI text + HTML. NO shell exec."""
    handler = _cli_dispatch().get(req.command)
    if handler is None:
        raise HTTPException(status_code=400, detail=f"unknown command: {req.command}")
    try:
        console = handler(req.args)
        text = console.export_text()
        html = console.export_html(inline_styles=True, code_format="<pre style=\"margin:0\">{code}</pre>")
        _log(f"CLI: {actor['username']} ran {req.command!r} {req.args!r}")
        return {"ok": True, "command": req.command, "args": req.args, "text": text, "html": html}
    except Exception as exc:
        log.exception("cli handler crashed")
        return {"ok": False, "command": req.command, "args": req.args, "error": str(exc)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
