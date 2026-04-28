"""Lightweight reachability/port scanner.

Pure-stdlib TCP-connect scan — no nmap dependency. If `nmap` is on PATH
we shell out to it for richer service detection (`-sV`); otherwise we
fall back to the connect scan. Either way the return shape is identical
so the dashboard doesn't care which ran.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .network import _service_name  # type: ignore[attr-defined]

DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 587, 631, 993, 995, 1080, 1433, 1521, 2049, 2375,
    3306, 3389, 5432, 5601, 5672, 5900, 5984, 6379, 8000, 8080,
    8443, 8888, 9000, 9042, 9092, 9200, 11211, 27017,
)


def _probe(host: str, port: int, timeout: float) -> tuple[int, bool]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return port, True
    except (OSError, socket.timeout):
        return port, False
    finally:
        s.close()


def _connect_scan(
    target: str,
    ports: tuple[int, ...],
    timeout: float = 0.6,
    max_workers: int = 64,
) -> list[dict[str, Any]]:
    open_ports: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe, target, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                open_ports.append({
                    "port": port,
                    "service": _service_name(port),
                    "state": "open",
                    "version": "",
                })
    return sorted(open_ports, key=lambda r: r["port"])


def _nmap_scan(target: str, ports: tuple[int, ...]) -> list[dict[str, Any]] | None:
    nmap = shutil.which("nmap")
    if not nmap:
        return None
    port_list = ",".join(str(p) for p in ports)
    try:
        proc = subprocess.run(
            [nmap, "-sV", "-Pn", "-T4", "--open", "-p", port_list, target],
            capture_output=True, text=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None

    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        # Lines look like: "22/tcp   open  ssh     OpenSSH 8.4p1"
        parts = line.split(maxsplit=3)
        if len(parts) < 3 or "/" not in parts[0] or parts[1] != "open":
            continue
        try:
            port = int(parts[0].split("/")[0])
        except ValueError:
            continue
        rows.append({
            "port": port,
            "service": parts[2].upper() if len(parts) > 2 else _service_name(port),
            "state": "open",
            "version": parts[3] if len(parts) > 3 else "",
        })
    return rows


def scan(target: str, ports: tuple[int, ...] | None = None) -> dict[str, Any]:
    """Scan `target`. Tries nmap for service-version, falls back to TCP-connect."""
    ports = ports or DEFAULT_PORTS
    started = __import__("time").time()

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        return {"target": target, "error": f"DNS lookup failed: {exc}", "open_ports": []}

    nmap_results = _nmap_scan(ip, ports)
    if nmap_results is not None:
        results = nmap_results
        engine = "nmap"
    else:
        results = _connect_scan(ip, ports)
        engine = "tcp-connect"

    return {
        "target": target,
        "resolved_ip": ip,
        "engine": engine,
        "duration_seconds": round(__import__("time").time() - started, 2),
        "open_ports": results,
    }
