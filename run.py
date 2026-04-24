import sys
import os
import subprocess
import time

def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py [cli|backend|frontend|both]")
        sys.exit(1)

    command = sys.argv[1].lower()
    root_dir = os.getcwd()

    # Use npx to ensure local binaries like vite are found
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"

    if command == "cli":
        os.environ["PYTHONPATH"] = os.path.join(root_dir, "backend")
        subprocess.run([sys.executable, "-m", "husn.src.cli"], cwd="backend")

    elif command == "backend":
        os.environ["PYTHONPATH"] = os.path.join(root_dir, "backend")
        subprocess.run([sys.executable, "main.py"], cwd="backend")

    elif command == "frontend":
        subprocess.run([npm_cmd, "run", "dev"], cwd="frontend")

    elif command == "both":
        print("🚀 Launching HUSN High-Professional Dual System...")

        # Start Backend
        print("Starting FastAPI Backend...")
        os.environ["PYTHONPATH"] = os.path.join(root_dir, "backend")
        backend_proc = subprocess.Popen([sys.executable, "main.py"], cwd="backend")

        time.sleep(2)

        # Start Frontend
        print("Starting React Frontend...")
        frontend_proc = subprocess.Popen([npm_cmd, "run", "dev"], cwd="frontend")

        print("\n--- HUSN SYSTEM READY ---")
        print("Backend: http://localhost:8000")
        print("Frontend: http://localhost:5173")
        print("-------------------------\n")

        try:
            # Start CLI in foreground
            print("Starting Interactive CLI...")
            subprocess.run([sys.executable, "-m", "husn.src.cli"], cwd="backend")
        finally:
            print("Cleaning up processes...")
            frontend_proc.terminate()
            backend_proc.terminate()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: cli, backend, frontend, both")
        sys.exit(1)

if __name__ == "__main__":
    main()
