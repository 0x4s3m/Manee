"""IP reputation lookup with two layers:

  1. Local known-bad CIDR list (Tor exit nodes, Spamhaus DROP, Cloudflare
     bogons, etc). Editable at runtime via `intel.reputation_lists` config
     entry — list of file paths, each containing one CIDR per line. Matches
     return source="local".
  2. AbuseIPDB API when `intel.abuseipdb_key` (resolved from env var) is
     set AND `intel.online` is true. Returns abuse_confidence (0-100) and
     report counts.

Anything we can't resolve returns score=0, classification='unknown' so the
frontend never special-cases.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("husn.intel.reputation")


def _cfg() -> dict[str, Any]:
    from husn.src import config
    return config.get("intel", {}) or {}


_lock = threading.Lock()
_cache: dict[str, dict[str, Any]] = {}
_local_nets: list[ipaddress._BaseNetwork] = []  # noqa: SLF001
_local_loaded_paths: tuple[str, ...] = ()


# Hardcoded baseline — small, useful even when no list files are configured.
# Cloudflare, common cloud egress, RFC bogons. NOT actually malicious — used
# to mark "infrastructure" in the dashboard so judges can distinguish.
_BASELINE_NOTABLE: dict[str, str] = {
    "1.1.1.1": "Cloudflare DNS",
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS",
    "9.9.9.9": "Quad9 DNS",
}


def _ensure_local_lists() -> None:
    global _local_nets, _local_loaded_paths
    paths = tuple(_cfg().get("reputation_lists", []) or [])
    if paths == _local_loaded_paths:
        return
    nets: list[ipaddress._BaseNetwork] = []
    for p in paths:
        try:
            for raw in Path(p).read_text(encoding="utf-8", errors="ignore").splitlines():
                s = raw.split("#", 1)[0].strip()
                if not s:
                    continue
                try:
                    nets.append(ipaddress.ip_network(s, strict=False))
                except ValueError:
                    continue
        except OSError as e:
            log.warning("[reputation] could not read list %s: %s", p, e)
    _local_nets = nets
    _local_loaded_paths = paths
    if nets:
        log.info("[reputation] loaded %d CIDRs from %d list(s)", len(nets), len(paths))


def _from_local(ip: str) -> dict[str, Any] | None:
    _ensure_local_lists()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if ip in _BASELINE_NOTABLE:
        return {"score": 0, "classification": _BASELINE_NOTABLE[ip], "source": "baseline", "reports": 0}
    for net in _local_nets:
        if addr in net:
            return {"score": 100, "classification": "Listed (blocklist)", "source": "local-list", "reports": 0}
    return None


def _from_abuseipdb(ip: str) -> dict[str, Any] | None:
    cfg = _cfg()
    if not cfg.get("online"):
        return None
    key = cfg.get("abuseipdb_key") or ""
    if not key:
        return None
    try:
        import requests
    except ImportError:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3.0,
        )
        if r.status_code != 200:
            return None
        d = (r.json() or {}).get("data") or {}
        score = int(d.get("abuseConfidenceScore", 0))
        return {
            "score": score,
            "classification": (
                "Malicious" if score >= 75 else
                "Suspicious" if score >= 25 else
                "Clean"
            ),
            "source": "abuseipdb",
            "reports": int(d.get("totalReports", 0)),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
        }
    except Exception as e:
        log.debug("[reputation] AbuseIPDB lookup failed: %s", e)
        return None


def lookup(ip: str) -> dict[str, Any]:
    if not ip:
        return {"score": 0, "classification": "unknown", "source": "empty", "reports": 0}
    ttl = int(_cfg().get("cache_ttl_seconds", 86400))
    now = time.time()
    with _lock:
        c = _cache.get(ip)
        if c and (now - c["_ts"]) < ttl:
            return {k: v for k, v in c.items() if k != "_ts"}
    result = _from_local(ip) or _from_abuseipdb(ip) or {
        "score": 0, "classification": "unknown", "source": "none", "reports": 0,
    }
    with _lock:
        _cache[ip] = {**result, "_ts": now}
    return result
