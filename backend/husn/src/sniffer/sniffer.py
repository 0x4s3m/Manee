"""Live packet capture + flow-feature extraction + AI scoring.

Architecture:
  * `scapy.sniff(prn=_on_packet, store=False)` runs in a daemon thread.
  * `_on_packet` updates the in-memory flow table keyed by the 5-tuple
    (src, dst, sport, dport, proto). Packets going src→dst are 'forward',
    dst→src are 'backward'.
  * A janitor thread (every JANITOR_INTERVAL seconds) walks the table and
    flushes any flow that's either expired (no packets in FLOW_TIMEOUT) or
    has accumulated MIN_PACKETS_FOR_SCORING bidirectional packets. Each
    flushed flow is converted into the 17-feature vector HusnAI was trained
    on and run through `ai.predict()` with `source_ips=[src]`.
  * If the AI flags it as a non-BENIGN anomaly, `responder.block_ip()` fires
    automatically — same path as a manual /simulate, except now the source
    IP is whoever was *actually* sending those packets.

Result: when a real attacker hits the box, the SIEM feed shows it within
~2 seconds without anyone touching the dashboard. No synthetic data.

Capabilities required:
  * CAP_NET_RAW + CAP_NET_ADMIN on the python binary, or run as root.
  * setup.sh / install.sh both grant these via setcap.
"""
from __future__ import annotations

import logging
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("husn.sniffer")

# -- tuning knobs --------------------------------------------------------
JANITOR_INTERVAL = 1.5          # seconds between flow-table sweeps
FLOW_TIMEOUT = 12.0             # flow expires after this many seconds idle
MIN_PACKETS_FOR_SCORING = 6     # don't bother scoring flows smaller than this
MAX_TRACKED_FLOWS = 4000        # memory cap; oldest evicted when exceeded
PREDICTIONS_RING = 200          # keep this many recent predictions for /sniffer/status
# ------------------------------------------------------------------------


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    started_at: float
    last_seen: float
    fwd_pkt_lens: list[int] = field(default_factory=list)
    bwd_pkt_lens: list[int] = field(default_factory=list)
    fwd_iats: list[float] = field(default_factory=list)
    last_fwd_ts: float = 0.0
    syn_count: int = 0
    ack_count: int = 0

    def packet_count(self) -> int:
        return len(self.fwd_pkt_lens) + len(self.bwd_pkt_lens)

    def to_features(self) -> dict[str, float]:
        """Map raw flow telemetry → the 17 features HusnAI knows about.
        Order/keys must match `husn.src.ai.model.HusnAI.features`."""
        duration = max(self.last_seen - self.started_at, 0.001)
        all_lens = self.fwd_pkt_lens + self.bwd_pkt_lens
        fwd = self.fwd_pkt_lens or [0]
        bwd = self.bwd_pkt_lens or [0]
        iat = self.fwd_iats or [0.0]
        total_bytes = sum(all_lens)
        return {
            "flow_duration": duration * 1_000_000,    # microseconds
            "total_fwd_pkts": len(self.fwd_pkt_lens),
            "total_bwd_pkts": len(self.bwd_pkt_lens),
            "fwd_pkt_len_max": max(fwd),
            "fwd_pkt_len_min": min(fwd),
            "fwd_pkt_len_mean": statistics.mean(fwd),
            "bwd_pkt_len_max": max(bwd),
            "bwd_pkt_len_min": min(bwd),
            "bwd_pkt_len_mean": statistics.mean(bwd),
            "flow_byts_s": total_bytes / duration,
            "flow_pkts_s": self.packet_count() / duration,
            "flow_iat_mean": statistics.mean(iat) * 1_000_000,
            "flow_iat_max": max(iat) * 1_000_000,
            "pkt_len_mean": statistics.mean(all_lens) if all_lens else 0,
            "pkt_len_std": statistics.pstdev(all_lens) if len(all_lens) > 1 else 0,
            "ack_flag_cnt": min(1, self.ack_count),
            "syn_flag_cnt": min(1, self.syn_count),
        }


class LiveSniffer:
    """Manages the sniff thread + janitor + counters."""

    def __init__(self, ai_provider=None):
        # `ai_provider` is a 0-arg callable returning the live HusnAI singleton.
        # Late-bound so we don't import HusnAI at module load (keeps startup fast
        # and avoids circular imports).
        self._ai_provider = ai_provider
        self._lock = threading.RLock()
        self._flows: dict[tuple, Flow] = {}
        self._sniff_thread: threading.Thread | None = None
        self._janitor_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._packets_seen = 0
        self._predictions = 0
        self._blocks_fired = 0
        self._started_at = 0.0
        self._error: str | None = None
        self._iface: str | None = None
        self._recent_preds: deque[dict[str, Any]] = deque(maxlen=PREDICTIONS_RING)

    # ---------- lifecycle

    def start(self, ai_provider=None) -> None:
        if ai_provider is not None:
            self._ai_provider = ai_provider
        with self._lock:
            if self._sniff_thread is not None:
                return
            try:
                self._cfg()  # validate config can be read
            except Exception as e:
                self._error = f"config error: {e}"
                log.warning("[sniffer] %s", self._error)
                return
            cfg = self._cfg()
            if not cfg.get("enabled"):
                log.info("[sniffer] disabled in config; not starting.")
                return

            try:
                # Touch scapy to confirm it's importable + has caps.
                from scapy.all import sniff  # noqa: F401
            except Exception as e:
                self._error = f"scapy unavailable: {e}"
                log.warning("[sniffer] %s", self._error)
                return

            self._stop.clear()
            self._started_at = time.time()
            self._iface = cfg.get("interface") or None  # None = scapy default

            self._sniff_thread = threading.Thread(target=self._run_sniff, daemon=True, name="husn-sniff")
            self._janitor_thread = threading.Thread(target=self._run_janitor, daemon=True, name="husn-janitor")
            self._sniff_thread.start()
            self._janitor_thread.start()
            log.info("[sniffer] started on iface=%s filter=%r", self._iface or "<default>", cfg.get("bpf_filter"))

    def stop(self) -> None:
        self._stop.set()
        for t in (self._sniff_thread, self._janitor_thread):
            if t is not None:
                t.join(timeout=2.0)
        self._sniff_thread = None
        self._janitor_thread = None

    # ---------- core loops

    def _run_sniff(self) -> None:
        try:
            from scapy.all import sniff
            cfg = self._cfg()
            sniff(
                iface=self._iface,
                filter=cfg.get("bpf_filter") or None,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _p: self._stop.is_set(),
            )
        except PermissionError as e:
            self._error = f"raw sockets denied — need CAP_NET_RAW or root ({e})"
            log.warning("[sniffer] %s", self._error)
        except Exception as e:
            self._error = f"sniff loop crashed: {e}"
            log.exception("[sniffer] sniff loop crashed")

    def _on_packet(self, pkt) -> None:
        try:
            from scapy.all import IP, TCP, UDP
        except Exception:
            return

        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        proto = "tcp" if pkt.haslayer(TCP) else ("udp" if pkt.haslayer(UDP) else f"ip/{ip.proto}")
        sport = dport = 0
        syn = ack = 0
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            sport, dport = int(t.sport), int(t.dport)
            flags = int(t.flags)
            syn = 1 if flags & 0x02 else 0
            ack = 1 if flags & 0x10 else 0
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            sport, dport = int(u.sport), int(u.dport)

        now = time.time()
        plen = int(len(pkt))
        # Canonicalise the flow key — direction-agnostic — and remember
        # which way the packet was going so we can split fwd/bwd lists.
        a = (ip.src, ip.dst, sport, dport, proto)
        b = (ip.dst, ip.src, dport, sport, proto)
        with self._lock:
            self._packets_seen += 1
            if a in self._flows:
                key, forward = a, True
            elif b in self._flows:
                key, forward = b, False
            else:
                if len(self._flows) >= MAX_TRACKED_FLOWS:
                    # Evict the single oldest flow.
                    oldest = min(self._flows.values(), key=lambda f: f.last_seen, default=None)
                    if oldest is not None:
                        self._flows.pop((oldest.src, oldest.dst, oldest.sport, oldest.dport, oldest.proto), None)
                key, forward = a, True
                self._flows[a] = Flow(
                    src=ip.src, dst=ip.dst, sport=sport, dport=dport, proto=proto,
                    started_at=now, last_seen=now,
                )
            f = self._flows[key]
            f.last_seen = now
            f.syn_count += syn
            f.ack_count += ack
            if forward:
                if f.last_fwd_ts:
                    f.fwd_iats.append(now - f.last_fwd_ts)
                f.last_fwd_ts = now
                f.fwd_pkt_lens.append(plen)
            else:
                f.bwd_pkt_lens.append(plen)

    def _run_janitor(self) -> None:
        while not self._stop.wait(JANITOR_INTERVAL):
            try:
                self._sweep_and_score()
            except Exception:
                log.exception("[sniffer] janitor sweep failed")

    def _sweep_and_score(self) -> None:
        now = time.time()
        with self._lock:
            ready: list[Flow] = []
            for key, f in list(self._flows.items()):
                expired = (now - f.last_seen) > FLOW_TIMEOUT
                big_enough = f.packet_count() >= MIN_PACKETS_FOR_SCORING
                if expired or (big_enough and f.packet_count() % 12 == 0):
                    ready.append(f)
                if expired:
                    self._flows.pop(key, None)
        if not ready:
            return
        ai = self._ai_provider() if self._ai_provider else None
        if ai is None:
            return

        import pandas as pd
        rows = [f.to_features() for f in ready]
        df = pd.DataFrame(rows, columns=ai.features)
        try:
            preds = ai.predict(df, source_ips=[f.src for f in ready])
        except Exception:
            log.exception("[sniffer] AI predict() crashed on real flow batch")
            return

        with self._lock:
            self._predictions += len(preds)
            for f, p in zip(ready, preds):
                if p["is_anomaly"] and p["label"] != "BENIGN":
                    self._blocks_fired += 1
                self._recent_preds.appendleft({
                    "ts": now,
                    "src": f.src,
                    "dst": f.dst,
                    "dport": f.dport,
                    "proto": f.proto,
                    "pkts": f.packet_count(),
                    "label": p["label"],
                    "confidence": p["confidence"],
                    "is_anomaly": p["is_anomaly"],
                })

    # ---------- introspection

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._cfg().get("enabled", False),
                "running": self._sniff_thread is not None and self._sniff_thread.is_alive(),
                "interface": self._iface or self._cfg().get("interface") or "<default>",
                "bpf_filter": self._cfg().get("bpf_filter") or "",
                "started_at": self._started_at,
                "uptime_seconds": int(time.time() - self._started_at) if self._started_at else 0,
                "packets_seen": self._packets_seen,
                "active_flows": len(self._flows),
                "predictions": self._predictions,
                "blocks_fired": self._blocks_fired,
                "error": self._error,
                "recent_predictions": list(self._recent_preds),
            }

    def _cfg(self) -> dict[str, Any]:
        from husn.src import config
        return config.get("sniffer", {}) or {}


# Module-level singleton — main.py wires lifespan + the AI provider.
sniffer = LiveSniffer()
