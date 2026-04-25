import sys
import os
import subprocess
import time

def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py [cli|backend|frontend|both|target|exploit]")
        sys.exit(1)

    command = sys.argv[1].lower()
    root_dir = os.getcwd()

    # Use npx to ensure local binaries like vite are found
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"

    # Common Environment Setup
    os.environ["PYTHONPATH"] = os.path.join(root_dir, "backend")

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
        print("🛡️ Launching HUSN High-Professional Dual System & Demo Environment...")

        # 1. Start Backend
        print("[+] Starting FastAPI Backend...")
        backend_proc = subprocess.Popen([sys.executable, "main.py"], cwd="backend")

        # 2. Start Vulnerable Target (Port 9000)
        print("[+] Starting Vulnerable Target App...")
        target_proc = subprocess.Popen([sys.executable, "vuln_app.py"], cwd="backend")

        time.sleep(3)

        # 3. Start Frontend
        print("[+] Starting React Frontend...")
        frontend_proc = subprocess.Popen([npm_cmd, "run", "dev"], cwd="frontend")

        print("\n--- HUSN SYSTEM READY ---")
        print("Dashboard: http://localhost:5173")
        print("API & SIEM: http://localhost:8000")
        print("Target (Vuln): http://localhost:9000")
        print("-------------------------\n")

        try:
            # Start CLI in foreground for the user
            print("Starting Interactive CLI...")
            subprocess.run([sys.executable, "-m", "husn.src.cli"], cwd="backend")
        finally:
            print("Cleaning up demo processes...")
            frontend_proc.terminate()
            target_proc.terminate()
            backend_proc.terminate()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: cli, backend, frontend, both, target, exploit")
        sys.exit(1)

if __name__ == "__main__":
    main()
