"""Git-based self-update channel.

`check()` does a `git fetch` and reports how far behind we are without
mutating anything. `apply()` does the `git pull` + (optional) pip
re-install + (optional) systemd reload. Both are safe to call from any
thread.

The 5-minute scheduler runs `check()` and (if `auto_apply: true`)
`apply()`. Results land in an in-memory ring buffer the API exposes.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from husn.src import config

log = logging.getLogger("husn.updater")

# Repo root = three levels up from this file (backend/husn/src/updater/updater.py)
REPO_ROOT = Path(__file__).resolve().parents[4]

_history: deque[dict[str, Any]] = deque(maxlen=50)
_state_lock = threading.Lock()
_last_check: dict[str, Any] = {
    "checked_at": 0,
    "current_commit": "",
    "remote_commit": "",
    "behind": 0,
    "ahead": 0,
    "available": False,
    "message": "Not yet checked.",
}


@dataclass
class UpdaterStatus:
    enabled: bool
    interval_minutes: int
    auto_apply: bool
    repo_url: str
    branch: str
    last_check: dict[str, Any]
    history: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "interval_minutes": self.interval_minutes,
            "auto_apply": self.auto_apply,
            "repo_url": self.repo_url,
            "branch": self.branch,
            "last_check": self.last_check,
            "history": self.history,
        }


def _git_available() -> bool:
    return shutil.which("git") is not None and (REPO_ROOT / ".git").exists()


def _run(args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    proc = subprocess.run(
        args, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _record(action: str, ok: bool, message: str, extras: dict[str, Any] | None = None) -> dict[str, Any]:
    entry = {
        "ts": time.time(),
        "ts_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "action": action,
        "ok": ok,
        "message": message,
        **(extras or {}),
    }
    with _state_lock:
        _history.appendleft(entry)
    log.info("[updater] %s ok=%s — %s", action, ok, message)
    return entry


def check() -> dict[str, Any]:
    """Fetch and report how far behind/ahead the local checkout is."""
    if not _git_available():
        msg = "Skipped: not a git checkout (or git not installed)."
        _record("check", False, msg)
        return {**_last_check, "message": msg, "checked_at": time.time()}

    branch = config.get("updater.branch", "main") or "main"

    rc, _, err = _run(["git", "fetch", "--quiet", "origin", branch])
    if rc != 0:
        msg = f"git fetch failed: {err or 'unknown'}"
        _record("check", False, msg)
        return {**_last_check, "message": msg, "checked_at": time.time()}

    _, current, _ = _run(["git", "rev-parse", "HEAD"])
    _, remote, _ = _run(["git", "rev-parse", f"origin/{branch}"])
    _, counts, _ = _run(["git", "rev-list", "--left-right", "--count", f"HEAD...origin/{branch}"])
    try:
        ahead_str, behind_str = counts.split()
        ahead, behind = int(ahead_str), int(behind_str)
    except ValueError:
        ahead, behind = 0, 0

    available = behind > 0
    msg = (
        f"Up to date with origin/{branch}." if not available
        else f"{behind} commit(s) behind origin/{branch}."
    )
    snapshot = {
        "checked_at": time.time(),
        "current_commit": current[:12],
        "remote_commit": remote[:12],
        "behind": behind,
        "ahead": ahead,
        "available": available,
        "branch": branch,
        "message": msg,
    }
    with _state_lock:
        _last_check.update(snapshot)
    _record("check", True, msg, {"behind": behind, "ahead": ahead})
    return snapshot


def apply() -> dict[str, Any]:
    """Pull + reinstall deps if requirements.txt changed. Caller is responsible
    for restarting the service (e.g. systemctl restart husn-backend)."""
    if not _git_available():
        return _record("apply", False, "Skipped: not a git checkout.")

    branch = config.get("updater.branch", "main") or "main"

    # Refuse to overwrite local changes.
    rc, status, _ = _run(["git", "status", "--porcelain"])
    if rc == 0 and status.strip():
        return _record("apply", False, "Refusing to pull: working tree is dirty.",
                       {"dirty_files": status.splitlines()})

    # Capture old requirements hash, if present.
    req_path = REPO_ROOT / "backend" / "requirements.txt"
    old_req = req_path.read_bytes() if req_path.exists() else b""

    rc, out, err = _run(["git", "pull", "--ff-only", "origin", branch], timeout=120)
    if rc != 0:
        return _record("apply", False, f"git pull failed: {err or out or 'unknown'}")

    extras: dict[str, Any] = {"git_output": out.splitlines()[-5:]}

    new_req = req_path.read_bytes() if req_path.exists() else b""
    if new_req and new_req != old_req:
        # Try to update deps in the venv that's running us.
        import sys
        rc2, _, err2 = _run([sys.executable, "-m", "pip", "install", "-q", "-r", str(req_path)], timeout=300)
        extras["pip"] = "ok" if rc2 == 0 else f"failed: {err2}"

    return _record("apply", True, "Update applied. Restart the service to load new code.", extras)


def status() -> dict[str, Any]:
    return UpdaterStatus(
        enabled=bool(config.get("updater.enabled", True)),
        interval_minutes=int(config.get("updater.interval_minutes", 5)),
        auto_apply=bool(config.get("updater.auto_apply", False)),
        repo_url=config.get("updater.repo_url", "") or "",
        branch=config.get("updater.branch", "main") or "main",
        last_check=dict(_last_check),
        history=list(_history),
    ).to_dict()


# ----------------------------------------------------------------------
# Background scheduler
# ----------------------------------------------------------------------

_scheduler = None


def start_scheduler() -> None:
    """Boot the 5-minute background check. Idempotent — safe to call twice."""
    global _scheduler
    if _scheduler is not None:
        return
    if not config.get("updater.enabled", True):
        log.info("[updater] disabled in config; scheduler not starting.")
        return

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        log.warning("[updater] apscheduler not installed; scheduler disabled.")
        return

    interval = int(config.get("updater.interval_minutes", 5))
    auto_apply = bool(config.get("updater.auto_apply", False))

    sched = BackgroundScheduler(daemon=True, timezone="UTC")

    def _tick() -> None:
        result = check()
        if auto_apply and result.get("available"):
            apply()

    sched.add_job(_tick, "interval", minutes=interval, id="husn-update", next_run_time=None)
    sched.start()
    _scheduler = sched
    log.info("[updater] scheduler started — every %d min, auto_apply=%s", interval, auto_apply)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
