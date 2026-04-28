"""Multi-port TCP honeypot.

Opens listeners on configured ports. Any inbound connection:
  1. Sends a fake banner (configurable per-port).
  2. Logs the source IP + port + service.
  3. Calls `responder.block_ip(...)` with attack_type='Honeypot Probe',
     severity='High' — which also fires the alert email and adds the IP
     to /blocked.
  4. Closes the connection.

Safety rails:
  * Won't bind a port that's already in use (psutil pre-check).
  * Whitelisted source IPs (loopback, configured admin IPs) are NOT blocked.
  * Per-IP debounce so a single nmap doesn't trigger 30 emails — handled by
    the existing notify throttle on the responder.

Default port set deliberately avoids 22/80/443 (real services). Targets
ports attackers love but you usually don't run.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from collections import deque
from typing import Any

import psutil

log = logging.getLogger("husn.honeypot")

DEFAULT_PORTS_AND_BANNERS: dict[int, str] = {
    23:    "Welcome to Linux 5.4.0\r\nlogin: ",
    21:    "220 ProFTPD 1.3.5e Server (Debian)\r\n",
    1433:  "",                                              # MSSQL — silent
    3306:  "5.7.31-log\x00",                                # MySQL banner
    5432:  "",                                              # PostgreSQL — silent
    6379:  "-ERR unknown command\r\n",                      # Redis
    9200:  "{\"name\":\"node-1\",\"cluster_name\":\"husn-honeypot\"}\n",  # Elasticsearch
    27017: "",                                              # MongoDB — silent
}

EVENT_RING = 200


class Honeypot:
    def __init__(self, responder_provider=None):
        # 0-arg callable returning the live DefenseResponse; late-bound to
        # avoid circular imports.
        self._responder_provider = responder_provider
        self._lock = threading.RLock()
        self._listeners: dict[int, socket.socket] = {}
        self._threads: dict[int, threading.Thread] = {}
        self._stop = threading.Event()
        self._connections_total = 0
        self._blocks_fired = 0
        self._started_at = 0.0
        self._events: deque[dict[str, Any]] = deque(maxlen=EVENT_RING)
        self._error: str | None = None

    # ---------- lifecycle

    def start(self, responder_provider=None) -> None:
        if responder_provider is not None:
            self._responder_provider = responder_provider
        cfg = self._cfg()
        if not cfg.get("enabled"):
            log.info("[honeypot] disabled in config; not starting.")
            return
        with self._lock:
            if self._listeners:
                return
            self._stop.clear()
            self._started_at = time.time()

        ports_cfg: dict[int, str] = self._resolved_ports()
        in_use = self._listening_ports_now()
        for port, banner in ports_cfg.items():
            if port in in_use:
                log.info("[honeypot] port %d already in use; skipping", port)
                continue
            self._open_listener(port, banner)
        if not self._listeners:
            self._error = "no honeypot ports could be opened (all in use or perms)"
            log.warning("[honeypot] %s", self._error)
        else:
            log.info("[honeypot] listening on %s", sorted(self._listeners.keys()))

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for s in self._listeners.values():
                try:
                    s.close()
                except Exception:
                    pass
            self._listeners.clear()
            for t in self._threads.values():
                t.join(timeout=1.0)
            self._threads.clear()

    # ---------- internals

    def _cfg(self) -> dict[str, Any]:
        from husn.src import config
        return config.get("honeypot", {}) or {}

    def _resolved_ports(self) -> dict[int, str]:
        cfg = self._cfg()
        configured = cfg.get("ports")
        if not configured:
            return dict(DEFAULT_PORTS_AND_BANNERS)
        out: dict[int, str] = {}
        for entry in configured:
            if isinstance(entry, int):
                out[entry] = DEFAULT_PORTS_AND_BANNERS.get(entry, "")
            elif isinstance(entry, dict):
                p = int(entry.get("port", 0))
                if p > 0:
                    out[p] = str(entry.get("banner", ""))
        return out

    def _listening_ports_now(self) -> set[int]:
        used: set[int] = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == psutil.CONN_LISTEN and c.laddr:
                    used.add(c.laddr.port)
        except Exception:
            pass
        return used

    def _open_listener(self, port: int, banner: str) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(16)
            s.settimeout(1.0)
        except (PermissionError, OSError) as e:
            log.info("[honeypot] could not bind port %d: %s", port, e)
            return
        with self._lock:
            self._listeners[port] = s
            t = threading.Thread(
                target=self._accept_loop, args=(port, s, banner),
                daemon=True, name=f"husn-honeypot-{port}",
            )
            self._threads[port] = t
            t.start()

    def _accept_loop(self, port: int, s: socket.socket, banner: str) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except OSError:
                return  # socket closed during shutdown
            ip = addr[0] if addr else ""
            threading.Thread(
                target=self._handle_connection, args=(conn, ip, port, banner),
                daemon=True,
            ).start()

    def _handle_connection(self, conn: socket.socket, ip: str, port: int, banner: str) -> None:
        try:
            try:
                if banner:
                    conn.sendall(banner.encode("utf-8", errors="ignore"))
                conn.settimeout(2.0)
                # Read up to 256 bytes of whatever the attacker tried to send.
                try:
                    payload = conn.recv(256).decode("utf-8", errors="replace")
                except (socket.timeout, OSError):
                    payload = ""
            finally:
                try: conn.close()
                except Exception: pass

            with self._lock:
                self._connections_total += 1
                event = {
                    "ts": time.time(),
                    "src_ip": ip, "dst_port": port,
                    "service": _service_name(port),
                    "payload_preview": payload[:120] if payload else "",
                }
                self._events.appendleft(event)

            log.info("[honeypot] hit ip=%s port=%d payload=%r", ip, port, payload[:80])

            responder = self._responder_provider() if self._responder_provider else None
            if responder is not None:
                # The responder honours its own whitelist (loopback, configured
                # CIDRs) so we don't need to duplicate it here.
                try:
                    result = responder.block_ip(
                        ip,
                        attack_type="Honeypot Probe",
                        severity="High",
                        confidence=1.0,
                        target=f"honeypot:{port}",
                    )
                    if result.get("ok"):
                        with self._lock:
                            self._blocks_fired += 1
                except Exception:
                    log.exception("[honeypot] block_ip failed")
        except Exception:
            log.exception("[honeypot] connection handler crashed")

    # ---------- introspection

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._cfg().get("enabled", False),
                "running": bool(self._listeners),
                "listening_ports": sorted(self._listeners.keys()),
                "connections_total": self._connections_total,
                "blocks_fired": self._blocks_fired,
                "started_at": self._started_at,
                "uptime_seconds": int(time.time() - self._started_at) if self._started_at else 0,
                "events": list(self._events),
                "error": self._error,
            }


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "unknown"


# Module-level singleton.
honeypot = Honeypot()
