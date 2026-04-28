"""Runtime allow/deny lists for IPs and countries.

Four lists, all editable at runtime, persisted to a YAML file:

    ip_whitelist        — never block these IPs (CIDR-aware)
    ip_blacklist        — always block on first sight, regardless of AI verdict
    country_whitelist   — ISO-2 country codes whose IPs are never blocked
    country_blacklist   — ISO-2 country codes whose IPs are always blocked

`runtime.yml` lives next to the active config (e.g. `/etc/husn/runtime.yml`).
The file is created on first write. The responder consults this module on
every block_ip() call.

Thread-safe — every mutation goes through a single lock and atomically
replaces the file via tmp+rename.
"""
from __future__ import annotations

import ipaddress
import os
import threading
from pathlib import Path
from typing import Any

import yaml


_KIND_TO_KEY = {
    "ip-allow": "ip_whitelist",
    "ip-deny":  "ip_blacklist",
    "country-allow": "country_whitelist",
    "country-deny":  "country_blacklist",
}

VALID_KINDS = tuple(_KIND_TO_KEY.keys())

_lock = threading.RLock()
_state: dict[str, list[str]] | None = None
_path: Path | None = None


def _resolve_path() -> Path:
    from husn.src import config
    explicit = config.get("response.runtime_lists_path") or ""
    if explicit:
        return Path(explicit)
    cfg = config.loaded_from()
    if cfg:
        return cfg.parent / "runtime.yml"
    return Path("/etc/husn/runtime.yml")


def _load() -> dict[str, list[str]]:
    global _state, _path
    p = _resolve_path()
    _path = p
    if not p.exists():
        _state = {k: [] for k in _KIND_TO_KEY.values()}
        return _state
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        raw = {}
    _state = {k: list(raw.get(k) or []) for k in _KIND_TO_KEY.values()}
    return _state


def _ensure() -> dict[str, list[str]]:
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
    tmp.write_text(yaml.safe_dump(_state, sort_keys=False, allow_unicode=True), encoding="utf-8")
    os.replace(tmp, _path)


def reload() -> None:
    """Drop the in-memory cache so the next read picks up out-of-band edits."""
    global _state
    with _lock:
        _state = None


# ---------- public API

def state_path() -> Path:
    _ensure()
    return _path  # type: ignore[return-value]


def all_lists() -> dict[str, list[str]]:
    s = _ensure()
    with _lock:
        return {k: list(v) for k, v in s.items()}


def add(kind: str, value: str) -> bool:
    if kind not in _KIND_TO_KEY:
        raise ValueError(f"kind must be one of {VALID_KINDS}")
    value = (value or "").strip()
    if not value:
        raise ValueError("empty value")
    if kind.startswith("country"):
        value = value.upper()[:2]
        if len(value) != 2:
            raise ValueError("country must be a 2-letter ISO code")
    else:
        # validate IP / CIDR
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as e:
            raise ValueError(f"invalid IP/CIDR: {e}")
    s = _ensure()
    key = _KIND_TO_KEY[kind]
    with _lock:
        if value in s[key]:
            return False
        s[key].append(value)
        _flush()
    return True


def remove(kind: str, value: str) -> bool:
    if kind not in _KIND_TO_KEY:
        raise ValueError(f"kind must be one of {VALID_KINDS}")
    s = _ensure()
    key = _KIND_TO_KEY[kind]
    val_norm = (value or "").strip()
    if kind.startswith("country"):
        val_norm = val_norm.upper()[:2]
    with _lock:
        if val_norm not in s[key]:
            return False
        s[key].remove(val_norm)
        _flush()
    return True


# ---------- query helpers (used by responder)

def is_ip_allowed(ip: str) -> bool:
    """True if `ip` matches any entry in ip_whitelist (CIDR-aware)."""
    s = _ensure()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in s["ip_whitelist"]:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if addr in net:
                return True
        except ValueError:
            continue
    return False


def is_ip_denied(ip: str) -> bool:
    s = _ensure()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in s["ip_blacklist"]:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_country_allowed(country_code: str | None) -> bool:
    if not country_code:
        return False
    s = _ensure()
    return country_code.upper() in s["country_whitelist"]


def is_country_denied(country_code: str | None) -> bool:
    if not country_code:
        return False
    s = _ensure()
    return country_code.upper() in s["country_blacklist"]
