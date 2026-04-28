"""SOC Analyst chatbot — uses the shared husn.src.llm client (DeepSeek).

The chatbot has live access to Husn's current state (blocked IPs,
sniffer/honeypot status, recent events). On every turn we build a fresh
system prompt that snapshots the box, plus a per-session history.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any

from husn.src import llm

log = logging.getLogger("husn.chat")

DEFAULT_MAX_HISTORY = 12

_sessions: dict[str, deque[dict[str, str]]] = {}
_lock = threading.RLock()


def _max_history() -> int:
    from husn.src import config
    return int((config.get("chat", {}) or {}).get("max_history") or DEFAULT_MAX_HISTORY)


def is_configured() -> bool:
    return llm.is_configured()


# ---------- live snapshot for the system prompt

def _snapshot() -> str:
    parts: list[str] = []
    try:
        from husn.src.system import hardware
        s = hardware.snapshot()
        parts.append(f"HOST: {s['os']['hostname']} ({s['os']['system']} {s['os']['release']}) "
                     f"· CPU {s['cpu']['usage_percent']}% · RAM {s['memory']['percent']}%")
    except Exception: pass

    try:
        from husn.src.sniffer.sniffer import sniffer
        ss = sniffer.status()
        parts.append(f"SNIFFER: running={ss['running']} packets_seen={ss['packets_seen']} "
                     f"flows={ss['active_flows']} predictions={ss['predictions']} "
                     f"blocks_fired={ss['blocks_fired']}")
    except Exception: pass

    try:
        from husn.src.honeypot.server import honeypot
        hs = honeypot.status()
        parts.append(f"HONEYPOT: running={hs['running']} ports={hs.get('listening_ports')} "
                     f"hits={hs['connections_total']} blocks_fired={hs['blocks_fired']}")
    except Exception: pass

    try:
        import main  # type: ignore
        rows = main.ai.responder.list_blocked()
        if rows:
            blocked = "\n".join(
                f"  - {r['ip']}: {r['attack_type']} (severity={r['severity']}, conf={r.get('confidence',0):.0%})"
                for r in rows[:10]
            )
            parts.append(f"BLOCKED IPs ({len(rows)} total, top 10):\n{blocked}")
        else:
            parts.append("BLOCKED IPs: none currently")
    except Exception: pass

    try:
        from husn.src.notify import settings as ns
        nss = ns.get()
        parts.append(f"NOTIFY: paused={nss['is_paused']} (for {nss['paused_for_seconds']}s) · min_severity={nss['min_severity']}")
    except Exception: pass

    return "\n".join(parts) or "(no live data available)"


def _system_prompt() -> str:
    return f"""You are Husn's SOC Analyst Assistant — an AI cyber-defense advisor
embedded inside the Husn (حصن) Intelligent Cyber Defense System.

Help the operator understand what's happening on the box right now,
suggest investigation steps, recommend defensive actions (e.g. add to
whitelist/blacklist, raise severity threshold, pause notifications),
and explain attack patterns.

RULES:
- Be concise and actionable. Use bullet points + bold for key facts.
- Bilingual: respond in whichever language the operator uses (English or Arabic).
- Reference specific IPs, counts, and metrics from the snapshot below.
  NEVER invent data.
- If asked to take an action (block X, change config), give the exact
  dashboard step or curl command — don't claim to have done it yourself.
- Format with markdown.

────────── LIVE SYSTEM SNAPSHOT (refreshed every turn) ──────────
{_snapshot()}
─────────────────────────────────────────────────────────────────

Current time (UTC): {time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())}
"""


# ---------- sessions

def _get_history(session_id: str) -> deque:
    with _lock:
        if session_id not in _sessions:
            _sessions[session_id] = deque(maxlen=_max_history() * 2)
        return _sessions[session_id]


def reset_session(session_id: str) -> None:
    with _lock:
        _sessions.pop(session_id, None)


def chat(session_id: str, user_message: str) -> dict[str, Any]:
    user_message = (user_message or "").strip()
    if not user_message:
        return {"ok": False, "reply": "", "error": "empty message"}

    hist = _get_history(session_id)
    hist.append({"role": "user", "content": user_message})

    result = llm.complete(system=_system_prompt(), messages=list(hist))

    if result.get("ok"):
        hist.append({"role": "assistant", "content": result["reply"]})
    else:
        # Don't poison history with the failed turn
        hist.pop()
    return result
