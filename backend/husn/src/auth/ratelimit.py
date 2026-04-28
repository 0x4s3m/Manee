"""Login rate limiting + brute-force lockout.

Two independent guards:

  * **per-IP rate limit** — sliding window of recent failed attempts. Once an
    IP exceeds `max_per_window`, further attempts return 429 with a
    retry-after hint. Hard floor against credential-stuffing scripts.

  * **per-username lockout** — if an account sees `lockout_threshold` failed
    attempts within `lockout_window`, it's locked for `lockout_duration`.
    Successful login clears the counter.

When an IP keeps failing past `auto_block_threshold` events, the responder
is invoked to drop them at iptables — Husn defends ITSELF using its own
defense system. Beautiful loop, real demo moment.

In-memory state is fine for our scale. If you ever scale to multiple
backend processes, swap the dicts for Redis. The interface stays the same.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

# ---------- tuning knobs (could be moved to config later)
WINDOW_SECONDS = 60          # per-IP sliding window
MAX_PER_WINDOW = 5           # max failed attempts per IP per window
LOCKOUT_THRESHOLD = 10       # failures before account lock
LOCKOUT_WINDOW = 300         # within this many seconds
LOCKOUT_DURATION = 900       # locked for this many seconds (15 min)
AUTO_BLOCK_THRESHOLD = 8     # at this many IP failures, fire iptables block


@dataclass
class _IpState:
    failures: deque[float] = field(default_factory=deque)   # ts of recent failures
    blocked_at_iptables: bool = False


@dataclass
class _UserState:
    failures: deque[float] = field(default_factory=deque)
    locked_until: float = 0.0


_lock = threading.RLock()
_by_ip: dict[str, _IpState] = defaultdict(_IpState)
_by_user: dict[str, _UserState] = defaultdict(_UserState)

# Late-bound — main.py wires this so we don't import responder at module load.
_responder_provider = None
_log_provider = None


def attach(responder_provider, log_provider) -> None:
    """Wire the responder + audit-logger callbacks. Called once from main."""
    global _responder_provider, _log_provider
    _responder_provider = responder_provider
    _log_provider = log_provider


# ---------- helpers

def _prune(d: deque, cutoff: float) -> None:
    while d and d[0] < cutoff:
        d.popleft()


def _audit(msg: str) -> None:
    if _log_provider is not None:
        try:
            _log_provider(msg)
        except Exception:
            pass


# ---------- public API

def check_ip_allowed(ip: str) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds). Call BEFORE attempting login."""
    now = time.time()
    with _lock:
        st = _by_ip[ip]
        _prune(st.failures, now - WINDOW_SECONDS)
        if len(st.failures) >= MAX_PER_WINDOW:
            oldest = st.failures[0]
            wait = max(1, int(WINDOW_SECONDS - (now - oldest)))
            return False, wait
    return True, 0


def check_user_allowed(username: str) -> tuple[bool, int]:
    """Return (allowed, retry_after_seconds). Call BEFORE checking password."""
    now = time.time()
    with _lock:
        st = _by_user[username.lower().strip()]
        if st.locked_until > now:
            return False, int(st.locked_until - now)
    return True, 0


def record_failure(username: str, ip: str) -> dict[str, Any]:
    """A login attempt failed. Update counters, possibly lock + auto-block."""
    now = time.time()
    actions: list[str] = []
    with _lock:
        ip_st = _by_ip[ip]
        ip_st.failures.append(now)
        _prune(ip_st.failures, now - WINDOW_SECONDS)

        user_key = username.lower().strip()
        u_st = _by_user[user_key]
        u_st.failures.append(now)
        _prune(u_st.failures, now - LOCKOUT_WINDOW)

        # Per-account lockout?
        if len(u_st.failures) >= LOCKOUT_THRESHOLD and u_st.locked_until <= now:
            u_st.locked_until = now + LOCKOUT_DURATION
            actions.append(f"account_locked:{user_key}")
            _audit(f"AUTH: locked account {user_key} for {LOCKOUT_DURATION}s after {len(u_st.failures)} failures")

        # Auto-block IP at iptables level?
        if (
            len(ip_st.failures) >= AUTO_BLOCK_THRESHOLD
            and not ip_st.blocked_at_iptables
            and _responder_provider is not None
        ):
            try:
                resp = _responder_provider()
                resp.block_ip(
                    ip,
                    attack_type="Brute Force Login",
                    severity="High",
                    confidence=1.0,
                    target="auth/login",
                )
                ip_st.blocked_at_iptables = True
                actions.append(f"iptables_blocked:{ip}")
                _audit(f"AUTH: auto-blocked {ip} at iptables after {len(ip_st.failures)} failed login attempts")
            except Exception:
                pass

        return {
            "ip_failures": len(ip_st.failures),
            "user_failures": len(u_st.failures),
            "actions": actions,
        }


def record_success(username: str, ip: str) -> None:
    """Successful login — clear counters for this user (IP keeps its history)."""
    with _lock:
        _by_user.pop(username.lower().strip(), None)


def status() -> dict[str, Any]:
    """Snapshot for /auth/security and the dashboard."""
    now = time.time()
    with _lock:
        active_ips = []
        for ip, st in _by_ip.items():
            _prune(st.failures, now - WINDOW_SECONDS)
            if st.failures or st.blocked_at_iptables:
                active_ips.append({
                    "ip": ip,
                    "failures": len(st.failures),
                    "iptables_blocked": st.blocked_at_iptables,
                })
        locked_users = []
        for u, st in _by_user.items():
            if st.locked_until > now:
                locked_users.append({
                    "username": u,
                    "locked_for_seconds": int(st.locked_until - now),
                    "failures": len(st.failures),
                })
        return {
            "config": {
                "window_seconds": WINDOW_SECONDS,
                "max_per_window": MAX_PER_WINDOW,
                "lockout_threshold": LOCKOUT_THRESHOLD,
                "lockout_duration": LOCKOUT_DURATION,
                "auto_block_threshold": AUTO_BLOCK_THRESHOLD,
            },
            "active_ips": active_ips,
            "locked_users": locked_users,
        }
