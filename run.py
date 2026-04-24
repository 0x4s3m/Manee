import sys
import os
import subprocess
import time

def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py [cli|dashboard|both]")
        sys.exit(1)

    command = sys.argv[1].lower()
    os.environ["PYTHONPATH"] = os.getcwd()

    if command == "cli":
        subprocess.run([sys.executable, "-m", "husn.src.cli"])
    elif command == "dashboard":
        subprocess.run([sys.executable, "-m", "streamlit", "run", "husn/src/dashboard.py"])
    elif command == "both":
        print("🚀 Launching HUSN Dual Interface...")
        # Start dashboard in background
        print("Starting Dashboard in background...")
        dashboard_proc = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "husn/src/dashboard.py"])

        time.sleep(2) # Give it a moment to start

        # Start CLI in foreground
        print("Starting Interactive CLI...")
        try:
            subprocess.run([sys.executable, "-m", "husn.src.cli"])
        finally:
            print("Cleaning up background processes...")
            dashboard_proc.terminate()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: cli, dashboard, both")
        sys.exit(1)

if __name__ == "__main__":
    main()
