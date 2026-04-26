#!/usr/bin/env python3
"""
Cyber Defense System - Web Dashboard Launcher
==========================================

Simple launcher script for the web dashboard.
Handles dependency installation and startup.
"""

import sys
import os
import subprocess
import time

def check_and_install_dependencies():
    """Check and install required dependencies."""
    print("Checking dependencies...")
    
    try:
        import flask
        import flask_socketio
        import psutil
        print("All dependencies are already installed")
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Installing dependencies...")
        
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("Failed to install dependencies")
            print("Please run: pip install -r requirements.txt")
            return False

def main():
    """Main launcher function."""
    print("Cyber Defense System - Web Dashboard")
    print("=" * 50)
    
    # Add project root to Python path
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # Check dependencies
    if not check_and_install_dependencies():
        input("Press Enter to exit...")
        return
    
    print("\nStarting web dashboard...")
    print("Dashboard will be available at: http://localhost:8080")
    print("Access from other devices using your IP address")
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        # Import and run the app
        from app import app, socketio
        
        # Get port from environment or default to 8080
        port = int(os.environ.get('PORT', 8080))
        
        # Start the server
        socketio.run(app, host='0.0.0.0', port=port, debug=False)
        
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as e:
        print(f"\nError starting server: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
