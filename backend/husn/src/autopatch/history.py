"""Auto Patch action audit log.

Every apply/reject/manual-edit lands here. Append-only, JSON-Lines on
disk so it's easy to grep / forward to a SIEM. Capped at 2000 entries
in the dashboard view (full file is preserved).
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

log = logging.getLogger("husn.autopatch.history")

_LOCK = threading.RLock()
_RING_SIZE = 2000
_ring: deque[dict[str, Any]] = deque(maxlen=_RING_SIZE)
_loaded = False


def _path() -> Path:
    from husn.src import config
    base = Path(config.get("paths.state_dir") or "/etc/husn")
    base.mkdir(parents=True, exist_ok=True)
    return base / "autopatch-history.jsonl"


def _load_once() -> None:
    global _loaded
    if _loaded:
        return
    p = _path()
    if not p.exists():
        _loaded = True
        return
    try:
        with p.open(encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    _ring.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
    except OSError:
        log.exception("[autopatch.history] failed to read %s", p)
    _loaded = True


def record(
    action: str,                    # 'apply' | 'reject' | 'manual' | 'llm-suggest'
    actor: str,                     # admin username
    issue_id: str,
    rule_id: str,
    file: str,
    line_number: int,
    outcome: str,                   # 'ok' | 'failed' | 'skipped'
    *,
    reason: str = "",
    before_hash: str = "",
    after_hash: str = "",
    detail: str = "",
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ts": time.time(),
        "ts_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "action": action,
        "actor": actor,
        "issue_id": issue_id,
        "rule_id": rule_id,
        "file": file,
        "line_number": line_number,
        "outcome": outcome,
        "reason": reason,
        "before_hash": before_hash,
        "after_hash": after_hash,
        "detail": detail,
    }
    with _LOCK:
        _load_once()
        _ring.append(entry)
        try:
            with _path().open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            log.exception("[autopatch.history] write failed")
    return entry


def recent(limit: int = 100) -> list[dict[str, Any]]:
    with _LOCK:
        _load_once()
        items = list(_ring)
    items.reverse()
    return items[:limit]


def count() -> int:
    with _LOCK:
        _load_once()
        return len(_ring)
