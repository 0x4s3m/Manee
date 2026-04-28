"""Husn local launcher.

Modes:
  cli       interactive CLI only
  backend   FastAPI on :8000
  frontend  Vite dev server on :5173
  target    intentionally vulnerable demo app on :9000
  exploit   one-shot exploit_demo.py
  both      backend + target + frontend (in background, output -> logs/) + CLI in foreground

In `both` mode, the backend, vulnerable target, and Vite all redirect their
output to logs/ so the CLI keeps the terminal to itself. Without that
redirection, every backend request log corrupts prompt_toolkit's prompt
and makes typing feel laggy.

Tail any of them in another terminal:
    tail -f logs/backend.log
    tail -f logs/vuln.log
    tail -f logs/frontend.log
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path


def _open_log(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Line-buffered so `tail -f` shows output promptly.
    return path.open("a", buffering=1)


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py [cli|backend|frontend|both|target|exploit]")
        sys.exit(1)

    command = sys.argv[1].lower()
    root_dir = Path(os.getcwd())

    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    os.environ["PYTHONPATH"] = str(root_dir / "backend")

    if command == "cli":
        subprocess.run([sys.executable, "-m", "husn.src.cli"], cwd="backend")

    elif command == "backend":
        subprocess.run([sys.executable, "main.py"], cwd="backend")

    elif command == "frontend":
        subprocess.run([npm_cmd, "run", "dev"], cwd="frontend")

    elif command == "target":
        print("🏛️ Starting Vulnerable Government Portal Simulation (Port 9000)...")
        subprocess.run([sys.executable, "vuln_app.py"], cwd="backend")

    elif command == "exploit":
        print("🚀 Executing Husn Exploit Demo sequence...")
        subprocess.run([sys.executable, "exploit_demo.py"])

    elif command == "both":
        log_dir = root_dir / "logs"
        backend_log = _open_log(log_dir / "backend.log")
        vuln_log = _open_log(log_dir / "vuln.log")
        frontend_log = _open_log(log_dir / "frontend.log")

        print("🛡️ Launching HUSN High-Professional Dual System & Demo Environment...")
        print(f"   logs → {log_dir}/")

        print("[+] Starting FastAPI Backend...")
        backend_proc = subprocess.Popen(
            [sys.executable, "main.py"], cwd="backend",
            stdout=backend_log, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )

        print("[+] Starting Vulnerable Target App...")
        target_proc = subprocess.Popen(
            [sys.executable, "vuln_app.py"], cwd="backend",
            stdout=vuln_log, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )

        time.sleep(2)

        print("[+] Starting React Frontend...")
        frontend_proc = subprocess.Popen(
            [npm_cmd, "run", "dev"], cwd="frontend",
            stdout=frontend_log, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )

        print("\n--- HUSN SYSTEM READY ---")
        print("Dashboard:    http://localhost:5173")
        print("API & SIEM:   http://localhost:8000")
        print("Target (Vuln): http://localhost:9000")
        print(f"Logs:         {log_dir}/")
        print("Tail any:     tail -f logs/backend.log")
        print("-------------------------\n")

        try:
            print("Starting Interactive CLI...\n")
            subprocess.run([sys.executable, "-m", "husn.src.cli"], cwd="backend")
        finally:
            print("\nCleaning up demo processes...")
            for proc in (frontend_proc, target_proc, backend_proc):
                try:
                    proc.terminate()
                except Exception:
                    pass
            for f in (backend_log, vuln_log, frontend_log):
                try:
                    f.close()
                except Exception:
                    pass
    else:
        print(f"Unknown command: {command}")
        print("Available commands: cli, backend, frontend, both, target, exploit")
        sys.exit(1)


if __name__ == "__main__":
    main()
