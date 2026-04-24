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

    # Streamlit configuration to suppress prompts
    st_args = [sys.executable, "-m", "streamlit", "run", "husn/src/dashboard.py",
               "--browser.gatherUsageStats", "false",
               "--server.headless", "true"]

    if command == "cli":
        subprocess.run([sys.executable, "-m", "husn.src.cli"])
    elif command == "dashboard":
        subprocess.run(st_args)
    elif command == "both":
        print("🚀 Launching HUSN Dual Interface...")
        # Start dashboard in background
        print("Starting Dashboard in background...")
        dashboard_proc = subprocess.Popen(st_args)

        time.sleep(3) # Give it more time to start

        # Start CLI in foreground
        print("Starting Interactive CLI...")
        try:
            subprocess.run([sys.executable, "-m", "husn.src.cli"])
        finally:
            print("Cleaning up background processes...")
            dashboard_proc.terminate()
            try:
                dashboard_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard_proc.kill()
    else:
        print(f"Unknown command: {command}")
        print("Available commands: cli, dashboard, both")
        sys.exit(1)

if __name__ == "__main__":
    main()
