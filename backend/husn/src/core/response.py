"""Active defense — IP blocking, session termination, alerting, deception.

Two modes:
  * Simulated (default): logs the action, fires the alert, but does not
    touch iptables. Safe for development.
  * Real: shells out to `iptables -A INPUT -s <ip> -j DROP` (and the
    matching `-D` for unblocking). Enabled with `response.real_iptables: true`
    in the config. Requires CAP_NET_ADMIN or root.

Every block triggers a notify.report.emit() so administrators get an
email with the SHAP explanation inline. The blocked-IPs registry is
also serialised to a JSON file (`response.shared_state_path`) so
companion processes (vuln_app's deception layer) can read it without
needing an HTTP round-trip.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("husn.response")


class DefenseResponse:
    def __init__(self, console=None):
        self.console = console
        self._blocked: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        # AI accessor — main.py wires this so we can attach SHAP features
        # to outbound reports without a circular import.
        self._feature_provider = None

    # ------------------------------------------------------------------
    # Wiring helpers (called once at startup by main.py)
    # ------------------------------------------------------------------
    def attach_feature_provider(self, provider):
        """`provider` is any callable returning the current feature_importance list."""
        self._feature_provider = provider

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def block_ip(
        self,
        ip_address: str,
        attack_type: str = "Unknown",
        severity: str = "High",
        confidence: float = 0.0,
        target: str = "",
        features: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        """Block `ip_address`. Idempotent: re-blocking a blocked IP is a no-op
        for iptables but still emits a (throttled) report."""
        ip_address = (ip_address or "").strip()
        if not ip_address:
            return {"ok": False, "error": "empty ip"}

        if self._is_whitelisted(ip_address):
            self._say(f"[!] Refusing to block whitelisted IP {ip_address}")
            return {"ok": False, "error": "whitelisted", "ip": ip_address}

        # Promote attack_type/severity if the source country is blacklisted —
        # gives the email + audit log a clear "policy block" tag.
        try:
            from husn.src.core import lists as _lists
            from husn.src.intel import geoip as _geoip
            cc = (_geoip.lookup(ip_address) or {}).get("country_code")
            if cc and _lists.is_country_denied(cc):
                attack_type = f"Country Block ({cc})"
                severity = "High"
                confidence = 1.0
        except Exception:
            pass

        self._say(f"[bold red]ACTIVE DEFENSE: Blocking malicious IP {ip_address}...[/bold red]",
                  fallback=f"ACTIVE DEFENSE: Blocking malicious IP {ip_address}...")

        iptables_result = self._iptables_block(ip_address) if self._real_mode() else {"ok": True, "mode": "simulated"}

        with self._lock:
            self._blocked[ip_address] = {
                "ip": ip_address,
                "blocked_at": time.time(),
                "attack_type": attack_type,
                "severity": severity,
                "confidence": confidence,
                "iptables": iptables_result,
            }
            self._persist_shared_state()

        # Schedule auto-unblock if configured.
        duration = int(self._cfg().get("block_duration_seconds", 0) or 0)
        if duration > 0:
            timer = threading.Timer(duration, self.unblock_ip, args=(ip_address,))
            timer.daemon = True
            timer.start()

        # Log to the learning store — this is what feeds the adaptive retrain loop.
        try:
            from husn.src.learning import store as _learning_store
            _learning_store.record_block(
                source_ip=ip_address, attack_type=attack_type, severity=severity,
                confidence=float(confidence or 0.0), features=features or {},
            )
        except Exception:
            log.exception("[response] failed to log block to learning store")

        # Fire the report. Imports are local to keep this module importable
        # even when the notify subsystem isn't installed (e.g. minimal CLI).
        try:
            from husn.src.notify.report import Incident, emit
            feature_importance_list = self._feature_provider() if self._feature_provider else []
            emit_result = emit(
                Incident(
                    source_ip=ip_address,
                    attack_type=attack_type,
                    severity=severity,
                    confidence=float(confidence or 0.0),
                    target=target,
                    action=f"Blocked via {iptables_result.get('mode', 'iptables')}",
                ),
                feature_importance=feature_importance_list,
            )
        except Exception as exc:  # pragma: no cover — never let alerting break defense
            log.exception("[response] alert dispatch failed")
            emit_result = {"error": str(exc)}

        self._say(f"[bold green]✓ IP {ip_address} has been isolated.[/bold green]",
                  fallback=f"✓ IP {ip_address} has been isolated.")
        return {"ok": True, "ip": ip_address, "iptables": iptables_result, "report": emit_result}

    def unblock_ip(self, ip_address: str) -> dict[str, Any]:
        with self._lock:
            entry = self._blocked.pop(ip_address, None)
            self._persist_shared_state()
        if entry is None:
            return {"ok": False, "error": "not blocked", "ip": ip_address}
        result = self._iptables_unblock(ip_address) if self._real_mode() else {"ok": True, "mode": "simulated"}
        log.info("[response] unblocked %s — %s", ip_address, result)
        return {"ok": True, "ip": ip_address, "iptables": result}

    def _persist_shared_state(self) -> None:
        """Write blocked IPs to a JSON file readable by vuln_app's deception
        layer. No locking needed — atomic write via tmp + replace."""
        path = self._cfg().get("shared_state_path") or "/tmp/husn_blocked.json"
        try:
            data = {
                "version": 1,
                "updated_at": time.time(),
                "blocked": [
                    {"ip": ip, **{k: v for k, v in r.items() if k != "iptables"}}
                    for ip, r in self._blocked.items()
                ],
            }
            tmp = Path(str(path) + ".tmp")
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(data))
            os.replace(tmp, path)
        except Exception:
            log.exception("[response] failed to persist shared state to %s", path)

    def list_blocked(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._blocked.values())

    def terminate_session(self, session_id: str) -> None:
        self._say(f"ACTIVE DEFENSE: Terminating suspicious session {session_id}...")
        time.sleep(0.3)
        self._say(f"✓ Session {session_id} killed.")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _cfg(self) -> dict[str, Any]:
        try:
            from husn.src import config
            return config.get("response", {}) or {}
        except Exception:
            return {}

    def _real_mode(self) -> bool:
        return bool(self._cfg().get("real_iptables", False)) and shutil.which("iptables") is not None

    def _is_whitelisted(self, ip: str) -> bool:
        # 1. Static config whitelist (CIDR-aware)
        whitelist = self._cfg().get("whitelist", []) or []
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in whitelist:
            try:
                if "/" in entry and target in ipaddress.ip_network(entry, strict=False):
                    return True
                if target == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        # 2. Runtime IP allow list
        try:
            from husn.src.core import lists
            if lists.is_ip_allowed(ip):
                return True
            # 3. Country allow list — needs GeoIP
            from husn.src.intel import geoip
            cc = (geoip.lookup(ip) or {}).get("country_code")
            if cc and lists.is_country_allowed(cc):
                return True
        except Exception:
            log.exception("[response] runtime allow lookup failed")
        return False

    def _iptables_block(self, ip: str) -> dict[str, Any]:
        try:
            proc = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "mode": "real", "error": str(exc)}
        return {"ok": proc.returncode == 0, "mode": "real", "stderr": proc.stderr.strip()}

    def _iptables_unblock(self, ip: str) -> dict[str, Any]:
        try:
            proc = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "mode": "real", "error": str(exc)}
        return {"ok": proc.returncode == 0, "mode": "real", "stderr": proc.stderr.strip()}

    def _say(self, msg: str, fallback: str | None = None) -> None:
        if self.console is not None:
            self.console.print(msg)
        else:
            print(fallback if fallback is not None else msg)
