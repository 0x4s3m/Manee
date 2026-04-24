import sys
import os
import subprocess

def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py [cli|dashboard]")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "cli":
        # Ensure PYTHONPATH is set to the current directory
        os.environ["PYTHONPATH"] = os.getcwd()
        subprocess.run([sys.executable, "-m", "husn.src.cli"])
    elif command == "dashboard":
        os.environ["PYTHONPATH"] = os.getcwd()
        # Use sys.executable -m streamlit for better portability
        subprocess.run([sys.executable, "-m", "streamlit", "run", "husn/src/dashboard.py"])
    else:
        print(f"Unknown command: {command}")
        print("Available commands: cli, dashboard")
        sys.exit(1)

if __name__ == "__main__":
    main()
