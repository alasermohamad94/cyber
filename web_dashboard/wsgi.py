"""
WSGI entry for production (Render, gunicorn).
"""
import os
import sys

WEB_DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(WEB_DASHBOARD_DIR)
for path in (PROJECT_ROOT, WEB_DASHBOARD_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)
os.chdir(WEB_DASHBOARD_DIR)

from app import app, start_background_threads

start_background_threads()
application = app
