"""
MAILJURY FULL SYSTEM LAUNCHER
Starts the FastAPI Backend and Vite Frontend concurrently and opens the browser.
"""
import subprocess
import webbrowser
import time
import sys
import os

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    frontend_dir = os.path.join(root_dir, "frontend")

    print("=" * 60)
    print("   ⚖️  STARTING MAILJURY COURTROOM DASHBOARD")
    print("=" * 60)

    # 1. Start Backend
    print("[1/2] Starting FastAPI Backend on http://localhost:8000...")
    backend_proc = subprocess.Popen([sys.executable, "backend/main.py"], cwd=root_dir)

    time.sleep(2)

    # 2. Start Frontend
    print("[2/2] Starting Vite Frontend on http://localhost:5173...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_proc = subprocess.Popen([npm_cmd, "run", "dev"], cwd=frontend_dir)

    time.sleep(3)
    print("\n[SUCCESS] Opening Dashboard at http://localhost:5173...")
    webbrowser.open("http://localhost:5173")

    print("\nMailJury is live! Press Ctrl+C in this terminal to stop.")
    try:
        backend_proc.wait()
    except KeyboardInterrupt:
        print("\nStopping services...")
        backend_proc.terminate()
        frontend_proc.terminate()

if __name__ == "__main__":
    main()
