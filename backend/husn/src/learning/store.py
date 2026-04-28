"""SQLite-backed event store for the learning loop.

Two tables:
  block_events   — every block, with the feature vector + admin feedback
  training_runs  — every retrain attempt, with accuracy and source

All access goes through this module so the schema lives in one place.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
_path: Path | None = None


SCHEMA = """
CREATE TABLE IF NOT EXISTS block_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    source_ip     TEXT NOT NULL,
    attack_type   TEXT,
    severity      TEXT,
    confidence    REAL,
    features_json TEXT,
    feedback      TEXT DEFAULT 'unconfirmed',
    feedback_by   TEXT,
    feedback_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_block_events_ts ON block_events(ts);
CREATE INDEX IF NOT EXISTS idx_block_events_feedback ON block_events(feedback);

CREATE TABLE IF NOT EXISTS training_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    total_samples   INTEGER,
    confirmed_count INTEGER,
    accuracy        REAL,
    duration_ms     INTEGER,
    source          TEXT,
    notes           TEXT
);
"""


def _resolve_path() -> Path:
    from husn.src import config
    explicit = config.get("learning.db_path") or ""
    if explicit:
        return Path(explicit)
    cfg_path = config.loaded_from()
    if cfg_path:
        return cfg_path.parent / "husn-learning.db"
    return Path(__file__).resolve().parents[4] / "config" / "husn-learning.db"


def _ensure() -> sqlite3.Connection:
    global _conn, _path
    with _lock:
        target = _resolve_path()
        if _conn is None or _path != target:
            target.parent.mkdir(parents=True, exist_ok=True)
            _conn = sqlite3.connect(str(target), check_same_thread=False)
            _conn.executescript(SCHEMA)
            _conn.commit()
            _path = target
        return _conn


def store_path() -> Path:
    _ensure()
    return _path  # type: ignore[return-value]


# ---------- writes

def record_block(
    *,
    source_ip: str,
    attack_type: str,
    severity: str,
    confidence: float,
    features: dict[str, float] | None = None,
) -> int:
    """Called by the responder on every block. Returns the new row id."""
    conn = _ensure()
    with _lock:
        cur = conn.execute(
            "INSERT INTO block_events (ts, source_ip, attack_type, severity, confidence, features_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), source_ip, attack_type, severity, float(confidence or 0),
             json.dumps(features or {})),
        )
        conn.commit()
        return int(cur.lastrowid or 0)


def set_feedback(event_id: int, feedback: str, by_user: str) -> bool:
    if feedback not in ("confirmed", "false_positive", "unconfirmed"):
        raise ValueError("feedback must be confirmed | false_positive | unconfirmed")
    conn = _ensure()
    with _lock:
        cur = conn.execute(
            "UPDATE block_events SET feedback=?, feedback_by=?, feedback_at=? WHERE id=?",
            (feedback, by_user, time.time(), event_id),
        )
        conn.commit()
        return cur.rowcount > 0


def record_training_run(
    *, total_samples: int, confirmed_count: int, accuracy: float,
    duration_ms: int, source: str, notes: str = "",
) -> int:
    conn = _ensure()
    with _lock:
        cur = conn.execute(
            "INSERT INTO training_runs (ts, total_samples, confirmed_count, accuracy, duration_ms, source, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time(), total_samples, confirmed_count, float(accuracy), int(duration_ms), source, notes),
        )
        conn.commit()
        return int(cur.lastrowid or 0)


# ---------- reads

def list_events(limit: int = 100) -> list[dict[str, Any]]:
    conn = _ensure()
    with _lock:
        rows = conn.execute(
            "SELECT id, ts, source_ip, attack_type, severity, confidence, feedback, feedback_by "
            "FROM block_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [
        {"id": r[0], "ts": r[1], "source_ip": r[2], "attack_type": r[3],
         "severity": r[4], "confidence": r[5], "feedback": r[6], "feedback_by": r[7]}
        for r in rows
    ]


def confirmed_features() -> list[tuple[dict[str, float], str]]:
    """Yield (features, attack_type) pairs for every confirmed block — used
    as the human-labelled training-data extension."""
    conn = _ensure()
    with _lock:
        rows = conn.execute(
            "SELECT features_json, attack_type FROM block_events WHERE feedback='confirmed'"
        ).fetchall()
    out: list[tuple[dict[str, float], str]] = []
    for fjson, label in rows:
        try:
            feats = json.loads(fjson) if fjson else {}
            if feats:
                out.append((feats, label))
        except json.JSONDecodeError:
            continue
    return out


def stats() -> dict[str, Any]:
    conn = _ensure()
    with _lock:
        total = conn.execute("SELECT COUNT(*) FROM block_events").fetchone()[0]
        confirmed = conn.execute(
            "SELECT COUNT(*) FROM block_events WHERE feedback='confirmed'"
        ).fetchone()[0]
        false_pos = conn.execute(
            "SELECT COUNT(*) FROM block_events WHERE feedback='false_positive'"
        ).fetchone()[0]
        runs = conn.execute(
            "SELECT id, ts, total_samples, confirmed_count, accuracy, duration_ms, source "
            "FROM training_runs ORDER BY id DESC LIMIT 10"
        ).fetchall()
    history = [
        {"id": r[0], "ts": r[1], "total_samples": r[2], "confirmed_count": r[3],
         "accuracy": r[4], "duration_ms": r[5], "source": r[6]}
        for r in runs
    ]
    last = history[0] if history else None
    return {
        "events_total": total,
        "events_confirmed": confirmed,
        "events_false_positive": false_pos,
        "events_unconfirmed": total - confirmed - false_pos,
        "training_runs": history,
        "last_accuracy": last["accuracy"] if last else None,
        "last_total_samples": last["total_samples"] if last else None,
        "store_path": str(store_path()),
    }
