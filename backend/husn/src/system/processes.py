"""Process introspection + suspicious-process heuristics.

The goal is *defender triage*, not malware classification — flag things a
human analyst should look at, with a one-line reason. False positives are
acceptable; missed obvious badness is not.
"""
from __future__ import annotations

import os
from typing import Any

import psutil

# Directories where it's normal for a binary to live. Anything else is
# at minimum worth a second look on a server.
_TRUSTED_DIRS = (
    "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/",
    "/bin/", "/sbin/", "/usr/lib/", "/opt/",
    # Python venvs and language runtimes:
    "/home/", "/root/.local/", "/var/lib/snapd/",
)

# Known-bad-when-seen process names. These are recurring crypto-miners and
# common Linux malware seen in the wild — if any of these are running on a
# server, alert immediately.
_KNOWN_BAD_NAMES = {
    "kdevtmpfsi", "kinsing", "xmrig", "minerd", "cpuminer",
    "ddgs", "watchdogs", "udevs", "kthreaddi", "khugepageds",
    "trojan", "perl5.10",
}

# Directories that should never host an executable on a normal server.
_SUSPICIOUS_PARENTS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")


def _classify(p: psutil.Process) -> tuple[bool, str]:
    """Return (is_suspicious, reason)."""
    try:
        name = (p.name() or "").lower()
        exe = p.exe() or ""
        cmdline = " ".join(p.cmdline() or [])
    except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
        return False, ""

    if name in _KNOWN_BAD_NAMES:
        return True, f"Known malicious process name: {name}"

    if exe and any(exe.startswith(d) for d in _SUSPICIOUS_PARENTS):
        return True, f"Executable lives in writable temp dir: {exe}"

    if exe and not any(exe.startswith(d) for d in _TRUSTED_DIRS):
        # Soft signal — only flag if it's also got a network connection,
        # to cut down on noise from desktop apps in /home/user/AppImages.
        try:
            if p.connections(kind="inet"):
                return True, f"Untrusted binary path with network activity: {exe}"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    # Crypto-miner heuristic: high CPU + obscured command line containing
    # well-known mining flags.
    miner_flags = ("--donate-level", "stratum+tcp", "xmr-stak", "--cpu-priority")
    if any(f in cmdline for f in miner_flags):
        return True, "Process arguments match cryptominer signature"

    return False, ""


def list_processes(limit: int = 100) -> list[dict[str, Any]]:
    """Return processes sorted by CPU%, with suspicious-flagging."""
    rows: list[dict[str, Any]] = []
    # First pass primes per-process CPU samplers; we read again below.
    for p in psutil.process_iter(["pid"]):
        try:
            p.cpu_percent(None)
        except psutil.Error:
            continue

    for p in psutil.process_iter(["pid", "name", "username", "memory_percent", "status"]):
        try:
            cpu = p.cpu_percent(None)
            suspicious, reason = _classify(p)
            try:
                conns = len(p.connections(kind="inet"))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                conns = -1
            rows.append({
                "pid": p.info["pid"],
                "name": p.info["name"] or "",
                "user": p.info["username"] or "",
                "status": p.info["status"] or "",
                "cpu_percent": round(cpu, 1),
                "memory_percent": round(p.info["memory_percent"] or 0, 1),
                "connections": conns,
                "suspicious": suspicious,
                "reason": reason,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    rows.sort(key=lambda r: (not r["suspicious"], -r["cpu_percent"]))
    return rows[:limit]


def suspicious_only() -> list[dict[str, Any]]:
    return [r for r in list_processes(limit=10000) if r["suspicious"]]


def kill(pid: int) -> dict[str, Any]:
    """Best-effort terminate. Requires sufficient privileges."""
    try:
        psutil.Process(pid).terminate()
        return {"ok": True, "pid": pid}
    except psutil.NoSuchProcess:
        return {"ok": False, "pid": pid, "error": "no such process"}
    except psutil.AccessDenied:
        return {"ok": False, "pid": pid, "error": f"access denied (run as root or with CAP_KILL)"}
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "pid": pid, "error": str(exc)}


if __name__ == "__main__":
    import json
    print(json.dumps(list_processes(20), indent=2))
