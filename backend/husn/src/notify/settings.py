"""Runtime notification settings — pause + severity threshold.

Two knobs the operator controls live from the dashboard:

  * `paused_until`   — Unix timestamp; mailer skips sending until then.
                       0 (or past) means notifications are active.
  * `min_severity`   — only blocks at this level or above generate emails.
                       Order: low < medium < high < critical.

Persisted to /etc/husn/notify.yml (or wherever the loader resolves to).
The mailer consults `should_send(severity)` on every dispatch.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

import yaml


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_lock = threading.RLock()
_state: dict[str, Any] | None = None
_path: Path | None = None


def _resolve_path() -> Path:
    from husn.src import config
    explicit = config.get("notify.settings_path") or ""
    if explicit:
        return Path(explicit)
    cfg = config.loaded_from()
    if cfg:
        return cfg.parent / "notify.yml"
    return Path("/etc/husn/notify.yml")


def _load() -> dict[str, Any]:
    global _state, _path
    p = _resolve_path()
    _path = p
    if not p.exists():
        _state = {"paused_until": 0, "min_severity": "low"}
        return _state
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        raw = {}
    _state = {
        "paused_until": float(raw.get("paused_until", 0) or 0),
        "min_severity": (raw.get("min_severity") or "low").lower(),
    }
    if _state["min_severity"] not in _SEVERITY_RANK:
        _state["min_severity"] = "low"
    return _state


def _ensure() -> dict[str, Any]:
    if _state is None:
        with _lock:
            if _state is None:
                _load()
    return _state  # type: ignore[return-value]


def _flush() -> None:
    if _state is None or _path is None:
        return
    tmp = _path.with_suffix(_path.suffix + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(yaml.safe_dump(_state, sort_keys=False), encoding="utf-8")
    os.replace(tmp, _path)


def reload() -> None:
    global _state
    with _lock:
        _state = None


# ---------- public API

def get() -> dict[str, Any]:
    s = _ensure()
    now = time.time()
    return {
        "paused_until": s["paused_until"],
        "paused_for_seconds": max(0, int(s["paused_until"] - now)),
        "is_paused": s["paused_until"] > now,
        "min_severity": s["min_severity"],
        "severity_options": list(_SEVERITY_RANK.keys()),
    }


def set_min_severity(value: str) -> str:
    value = (value or "").lower().strip()
    if value not in _SEVERITY_RANK:
        raise ValueError(f"min_severity must be one of {list(_SEVERITY_RANK.keys())}")
    s = _ensure()
    with _lock:
        s["min_severity"] = value
        _flush()
    return value


def pause(seconds: int) -> float:
    """Pause for N seconds. Pass 0 to resume; pass -1 for "forever" (~10 years)."""
    s = _ensure()
    now = time.time()
    if seconds == 0:
        until = 0.0
    elif seconds < 0:
        until = now + 10 * 365 * 86400
    else:
        until = now + int(seconds)
    with _lock:
        s["paused_until"] = until
        _flush()
    return until


def should_send(severity: str) -> tuple[bool, str]:
    """Return (allowed, reason). Used by mailer just before dispatch."""
    s = _ensure()
    now = time.time()
    if s["paused_until"] > now:
        wait = int(s["paused_until"] - now)
        return False, f"notifications paused for {wait}s"
    sev_rank = _SEVERITY_RANK.get((severity or "low").lower(), 0)
    min_rank = _SEVERITY_RANK[s["min_severity"]]
    if sev_rank < min_rank:
        return False, f"severity '{severity}' below threshold '{s['min_severity']}'"
    return True, "ok"
