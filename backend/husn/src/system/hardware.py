"""Hardware + OS introspection.

Cross-platform via `psutil` and `platform`. Designed to be cheap enough
to call on every dashboard poll (~once per 2s).
"""
from __future__ import annotations

import platform
import socket
import time
from typing import Any

import psutil


def _bytes_to_gb(n: int) -> float:
    return round(n / (1024 ** 3), 2)


def cpu_info() -> dict[str, Any]:
    # interval=None is non-blocking — returns the average since the previous
    # call. The first call after import returns 0.0; every subsequent call is
    # accurate and instant. Avoids a 100ms blocking sleep per snapshot, which
    # was making the CLI feel sluggish on each `sysinfo` and the dashboard
    # block briefly on every 5-second hardware poll.
    freq = psutil.cpu_freq()
    return {
        "model": platform.processor() or platform.machine(),
        "physical_cores": psutil.cpu_count(logical=False) or 0,
        "logical_cores": psutil.cpu_count(logical=True) or 0,
        "frequency_mhz": round(freq.current, 0) if freq else 0,
        "usage_percent": psutil.cpu_percent(interval=None),
        "load_average": list(psutil.getloadavg()) if hasattr(psutil, "getloadavg") else [],
    }


# Prime the cpu_percent sampler at import time so the first call from
# anywhere returns a real number instead of 0.0.
psutil.cpu_percent(interval=None)


def memory_info() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    return {
        "total_gb": _bytes_to_gb(vm.total),
        "used_gb": _bytes_to_gb(vm.used),
        "available_gb": _bytes_to_gb(vm.available),
        "percent": vm.percent,
        "swap_total_gb": _bytes_to_gb(sw.total),
        "swap_used_gb": _bytes_to_gb(sw.used),
        "swap_percent": sw.percent,
    }


def disk_info() -> list[dict[str, Any]]:
    out = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        out.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "total_gb": _bytes_to_gb(usage.total),
            "used_gb": _bytes_to_gb(usage.used),
            "percent": usage.percent,
        })
    return out


def network_interfaces() -> list[dict[str, Any]]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out = []
    for name, address_list in addrs.items():
        ipv4 = next((a.address for a in address_list if a.family == socket.AF_INET), None)
        mac = next((a.address for a in address_list if a.family == psutil.AF_LINK), None)
        stat = stats.get(name)
        out.append({
            "name": name,
            "ipv4": ipv4,
            "mac": mac,
            "is_up": stat.isup if stat else False,
            "speed_mbps": stat.speed if stat else 0,
        })
    return out


def os_info() -> dict[str, Any]:
    boot_ts = psutil.boot_time()
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "python": platform.python_version(),
        "boot_time": boot_ts,
        "uptime_seconds": int(time.time() - boot_ts),
    }


def snapshot() -> dict[str, Any]:
    """One-shot bundle of everything above. This is what the API serves."""
    return {
        "os": os_info(),
        "cpu": cpu_info(),
        "memory": memory_info(),
        "disks": disk_info(),
        "interfaces": network_interfaces(),
    }
