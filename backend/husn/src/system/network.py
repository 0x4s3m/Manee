"""Network introspection — listening ports, established connections, services.

Uses psutil only (no nmap/lsof dependency) so it works on a vanilla server.
"""
from __future__ import annotations

import socket
from typing import Any

import psutil

# IANA well-known ports -> human-readable service. Extend freely.
_WELL_KNOWN: dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 119: "NNTP", 123: "NTP", 135: "MS-RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Submission",
    631: "CUPS", 636: "LDAPS", 873: "rsync", 989: "FTPS", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MS-SQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2375: "Docker", 2376: "Docker-TLS", 3000: "Dev-HTTP",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5000: "UPnP",
    5060: "SIP", 5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes-API",
    7474: "Neo4j", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8086: "InfluxDB",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "HTTP-Alt",
    9042: "Cassandra", 9092: "Kafka", 9200: "Elasticsearch",
    9300: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    50000: "DB2",
}


def _service_name(port: int) -> str:
    if port in _WELL_KNOWN:
        return _WELL_KNOWN[port]
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "unknown"


def _proc_name(pid: int | None) -> str:
    if not pid:
        return ""
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


def listening_ports() -> list[dict[str, Any]]:
    """All sockets in LISTEN state, with the bound port and owning process."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, str, int]] = set()
    for c in psutil.net_connections(kind="inet"):
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        port = c.laddr.port
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        key = (port, proto, c.pid or 0)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "port": port,
            "protocol": proto,
            "address": c.laddr.ip,
            "service": _service_name(port),
            "pid": c.pid,
            "process": _proc_name(c.pid),
        })
    out.sort(key=lambda r: r["port"])
    return out


def established_connections(limit: int = 100) -> list[dict[str, Any]]:
    """Currently established inbound/outbound connections — useful for live triage."""
    out: list[dict[str, Any]] = []
    for c in psutil.net_connections(kind="inet"):
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        out.append({
            "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "remote": f"{c.raddr.ip}:{c.raddr.port}",
            "remote_ip": c.raddr.ip,
            "remote_port": c.raddr.port,
            "service": _service_name(c.laddr.port if c.laddr else 0),
            "pid": c.pid,
            "process": _proc_name(c.pid),
        })
    return out[:limit]


def connections_grouped() -> dict[str, Any]:
    """Established connections plus aggregations — fuels the Connections panel.

    Returns:
      established: full row list (capped)
      by_remote:   per remote IP — count, ports, services touched
      top_processes: per process — connection count, ports it owns
    """
    rows = established_connections(limit=200)
    by_remote: dict[str, dict[str, Any]] = {}
    by_proc: dict[str, dict[str, Any]] = {}
    for r in rows:
        ip = r["remote_ip"]
        agg = by_remote.setdefault(ip, {"remote_ip": ip, "count": 0, "ports": set(), "services": set(), "processes": set()})
        agg["count"] += 1
        agg["ports"].add(r["remote_port"])
        agg["services"].add(r["service"])
        if r["process"]:
            agg["processes"].add(r["process"])

        proc = r["process"] or "(unknown)"
        pagg = by_proc.setdefault(proc, {"process": proc, "pid": r["pid"], "count": 0, "remotes": set()})
        pagg["count"] += 1
        pagg["remotes"].add(ip)

    by_remote_list = sorted(
        ({**v, "ports": sorted(v["ports"]), "services": sorted(v["services"]), "processes": sorted(v["processes"])}
         for v in by_remote.values()),
        key=lambda x: x["count"], reverse=True,
    )
    by_proc_list = sorted(
        ({**v, "remotes": sorted(v["remotes"])} for v in by_proc.values()),
        key=lambda x: x["count"], reverse=True,
    )
    return {
        "established": rows,
        "total": len(rows),
        "by_remote": by_remote_list,
        "top_processes": by_proc_list[:10],
    }


def services() -> list[dict[str, Any]]:
    """De-duplicated view: one row per (process, port) — what's actually
    serving on this box."""
    by_proc: dict[tuple[int | None, str], list[int]] = {}
    for row in listening_ports():
        key = (row["pid"], row["process"])
        by_proc.setdefault(key, []).append(row["port"])
    out = []
    for (pid, name), ports in by_proc.items():
        out.append({
            "process": name or "(unknown)",
            "pid": pid,
            "ports": sorted(ports),
            "services": sorted({_service_name(p) for p in ports}),
        })
    return sorted(out, key=lambda r: r["process"])
