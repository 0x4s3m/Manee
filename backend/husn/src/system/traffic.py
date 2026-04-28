"""Real network-traffic sampler.

Background thread polls `psutil.net_io_counters(pernic=True)` once per
second, converts the cumulative byte/packet counters into per-second
deltas, and stores a 120-point sliding window per interface plus an
aggregate. Thread-safe; safe to call `latest()` / `history()` from any
HTTP handler at any time.

Replaces the previous `random.randint(...)` mock in /monitor with actual
host traffic, so the dashboard's live chart reflects what the box is
really seeing.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

import psutil

WINDOW_SECONDS = 120
SAMPLE_INTERVAL = 1.0


class TrafficSampler:
    def __init__(self, window_seconds: int = WINDOW_SECONDS):
        self.window = window_seconds
        self._lock = threading.RLock()
        self._totals: deque[dict[str, Any]] = deque(maxlen=window_seconds)
        self._series: dict[str, deque[dict[str, Any]]] = {}
        self._last_sample: dict[str, dict[str, Any]] = {}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started_at = 0.0

    # ---------------------------------------------------------- lifecycle

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            self._stop.clear()
            self._take_sample()  # prime the deltas
            self._started_at = time.time()
            self._thread = threading.Thread(target=self._loop, daemon=True, name="husn-traffic")
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        self._thread = None
        if t is not None:
            t.join(timeout=2.0)

    def _loop(self) -> None:
        while not self._stop.wait(SAMPLE_INTERVAL):
            try:
                self._take_sample()
            except Exception:
                # Never let a sampling glitch kill the thread.
                pass

    # ---------------------------------------------------------- sampling

    def _take_sample(self) -> None:
        now = time.time()
        per_iface = psutil.net_io_counters(pernic=True)
        with self._lock:
            agg_in = agg_out = 0
            agg_pin = agg_pout = 0
            for iface, snap in per_iface.items():
                last = self._last_sample.get(iface)
                if last is not None:
                    dt = max(now - last["ts"], 0.001)
                    bps_in = max(0, (snap.bytes_recv - last["bytes_recv"]) / dt)
                    bps_out = max(0, (snap.bytes_sent - last["bytes_sent"]) / dt)
                    pps_in = max(0, (snap.packets_recv - last["packets_recv"]) / dt)
                    pps_out = max(0, (snap.packets_sent - last["packets_sent"]) / dt)
                    agg_in += bps_in
                    agg_out += bps_out
                    agg_pin += pps_in
                    agg_pout += pps_out
                    self._series.setdefault(iface, deque(maxlen=self.window)).append({
                        "ts": now,
                        "bytes_in_per_s": int(bps_in),
                        "bytes_out_per_s": int(bps_out),
                        "packets_in_per_s": int(pps_in),
                        "packets_out_per_s": int(pps_out),
                    })
                self._last_sample[iface] = {
                    "ts": now,
                    "bytes_recv": snap.bytes_recv,
                    "bytes_sent": snap.bytes_sent,
                    "packets_recv": snap.packets_recv,
                    "packets_sent": snap.packets_sent,
                }
            # Only push an aggregate row once we have at least one delta.
            if any(self._series.values()):
                self._totals.append({
                    "ts": now,
                    "bytes_in_per_s": int(agg_in),
                    "bytes_out_per_s": int(agg_out),
                    "packets_in_per_s": int(agg_pin),
                    "packets_out_per_s": int(agg_pout),
                })

    # ---------------------------------------------------------- readers

    def latest(self) -> dict[str, Any]:
        with self._lock:
            if not self._totals:
                return {
                    "ts": time.time(),
                    "bytes_in_per_s": 0,
                    "bytes_out_per_s": 0,
                    "packets_in_per_s": 0,
                    "packets_out_per_s": 0,
                }
            return dict(self._totals[-1])

    def history(self, interface: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            src = self._series.get(interface, deque()) if interface else self._totals
            return [dict(r) for r in src]

    def interfaces(self) -> list[str]:
        with self._lock:
            return sorted(self._series.keys())

    def snapshot(self) -> dict[str, Any]:
        """Everything in one round-trip — used by /system/traffic."""
        with self._lock:
            return {
                "started_at": self._started_at,
                "window_seconds": self.window,
                "interfaces": sorted(self._series.keys()),
                "totals": [dict(r) for r in self._totals],
                "per_interface": {k: [dict(x) for x in v] for k, v in self._series.items()},
                "latest": self.latest(),
            }


# Module-level singleton. main.py starts/stops it via the FastAPI lifespan.
sampler = TrafficSampler()
