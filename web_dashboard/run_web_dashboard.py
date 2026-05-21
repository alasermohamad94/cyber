#!/usr/bin/env python3
"""Launcher for the Cyber Defense System web dashboard."""

import os
import subprocess
import sys

WEB_DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(WEB_DASHBOARD_DIR)
REQUIREMENTS = os.path.join(WEB_DASHBOARD_DIR, "requirements.txt")


def check_and_install_dependencies():
    print("Checking dependencies...")
    try:
        import flask  # noqa: F401
        import flask_socketio  # noqa: F401
        import psutil  # noqa: F401
        print("All dependencies are already installed")
        return True
    except ImportError as exc:
        print(f"Missing dependency: {exc}")
        print("Installing dependencies...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS],
                cwd=WEB_DASHBOARD_DIR,
            )
            print("Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("Failed to install dependencies")
            print(f"Please run: pip install -r {REQUIREMENTS}")
            return False


def main():
    print("Cyber Defense System - Web Dashboard")
    print("=" * 50)

    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    os.chdir(WEB_DASHBOARD_DIR)

    if not check_and_install_dependencies():
        input("Press Enter to exit...")
        return

    from security.config import get_bind_host, get_bind_port

    host = get_bind_host()
    port = get_bind_port()
    print("\nStarting web dashboard...")
    print(f"Login:     http://{host}:{port}/login")
    print(f"Dashboard: http://{host}:{port}/web_dashboard  (after login)")
    print("Default login: admin / changeme (override via CDS_ADMIN_* env vars)")
    print("Press Ctrl+C to stop the server")
    print("=" * 50)

    try:
        from app import app, socketio, start_background_threads

        start_background_threads()
        socketio.run(app, host=host, port=port, debug=False)
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as exc:
        print(f"\nError starting server: {exc}")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
