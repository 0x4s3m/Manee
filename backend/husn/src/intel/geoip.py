"""GeoIP lookup with three layers, in order of preference:

  1. Local MaxMind GeoLite2 City DB if `intel.geoip_db_path` is set and the
     `geoip2` package is importable. Pure offline. Best for production.
  2. ip-api.com (free, no auth, ~45 req/min) when `intel.online: true`.
     Cached aggressively to stay under the rate limit.
  3. Hardcoded private/loopback shortcuts so RFC1918 IPs return cleanly
     instead of erroring.

Anything we can't resolve returns the same shape with country='??' so the
frontend never has to special-case missing data.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("husn.intel.geoip")

CACHE_TTL_DEFAULT = 86400  # 24h


def _cfg() -> dict[str, Any]:
    from husn.src import config
    return config.get("intel", {}) or {}


_lock = threading.Lock()
_cache: dict[str, dict[str, Any]] = {}
_mmdb_reader = None
_mmdb_path: str | None = None


# Country code → emoji flag. Two-letter ISO codes only.
def _flag(cc: str | None) -> str:
    if not cc or len(cc) != 2:
        return "🏳️"
    return chr(0x1F1E6 + ord(cc[0].upper()) - ord("A")) + chr(0x1F1E6 + ord(cc[1].upper()) - ord("A"))


def _shortcut(ip: str) -> dict[str, Any] | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return _make("Loopback", "Loopback", None, None, None, "loopback")
    if addr.is_private:
        return _make("Private network", "RFC1918", None, None, None, "private")
    if addr.is_link_local:
        return _make("Link-local", None, None, None, None, "link-local")
    if addr.is_multicast:
        return _make("Multicast", None, None, None, None, "multicast")
    if addr.is_reserved:
        return _make("Reserved", None, None, None, None, "reserved")
    return None


def _make(country: str | None, city: str | None, lat: float | None, lon: float | None,
          asn: str | None, source: str, country_code: str | None = None) -> dict[str, Any]:
    return {
        "country": country or "Unknown",
        "country_code": (country_code or "").upper() or None,
        "flag": _flag(country_code),
        "city": city or "",
        "latitude": lat,
        "longitude": lon,
        "asn": asn or "",
        "source": source,
    }


# ---------- MaxMind path

def _ensure_mmdb():
    global _mmdb_reader, _mmdb_path
    path = _cfg().get("geoip_db_path") or ""
    if not path or path == _mmdb_path:
        return _mmdb_reader
    try:
        import geoip2.database  # type: ignore
    except ImportError:
        log.info("[geoip] geoip2 package not installed; MaxMind path skipped")
        return None
    if not Path(path).exists():
        log.info("[geoip] MaxMind DB not found at %s — skipping", path)
        return None
    try:
        _mmdb_reader = geoip2.database.Reader(path)
        _mmdb_path = path
        log.info("[geoip] MaxMind DB loaded: %s", path)
        return _mmdb_reader
    except Exception as e:
        log.warning("[geoip] failed to load %s: %s", path, e)
        return None


def _from_mmdb(ip: str) -> dict[str, Any] | None:
    reader = _ensure_mmdb()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        return _make(
            country=r.country.name,
            city=r.city.name,
            lat=float(r.location.latitude) if r.location.latitude is not None else None,
            lon=float(r.location.longitude) if r.location.longitude is not None else None,
            asn=None,  # GeoLite2-City doesn't include ASN; ASN DB is separate
            source="maxmind",
            country_code=r.country.iso_code,
        )
    except Exception:
        return None


# ---------- ip-api.com online path

def _from_ip_api(ip: str) -> dict[str, Any] | None:
    if not _cfg().get("online", False):
        return None
    try:
        import requests
    except ImportError:
        return None
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,lat,lon,as"},
            timeout=2.5,
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("status") != "success":
            return None
        return _make(
            country=d.get("country"),
            city=d.get("city"),
            lat=d.get("lat"),
            lon=d.get("lon"),
            asn=d.get("as"),
            source="ip-api",
            country_code=d.get("countryCode"),
        )
    except Exception as e:
        log.debug("[geoip] ip-api lookup failed: %s", e)
        return None


# ---------- public API

def lookup(ip: str) -> dict[str, Any]:
    if not ip:
        return _make(None, None, None, None, None, "empty")
    sc = _shortcut(ip)
    if sc is not None:
        return sc

    ttl = int(_cfg().get("cache_ttl_seconds", CACHE_TTL_DEFAULT))
    now = time.time()
    with _lock:
        cached = _cache.get(ip)
        if cached and (now - cached["_ts"]) < ttl:
            return {k: v for k, v in cached.items() if k != "_ts"}

    result = _from_mmdb(ip) or _from_ip_api(ip) or _make("Unknown", None, None, None, None, "none", country_code="")
    with _lock:
        _cache[ip] = {**result, "_ts": now}
    return result


def lookup_many(ips: list[str]) -> dict[str, dict[str, Any]]:
    return {ip: lookup(ip) for ip in ips}
