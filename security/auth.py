"""
Session-based authentication and authorization for the web dashboard.
"""

from functools import wraps
from typing import Callable, Dict, Optional, Tuple

from flask import jsonify, redirect, request, session, url_for

from security.config import get_user_directory
from security.roles import Role, role_has_permission, resolve_role_for_user


def login_user(username: str, role: str) -> None:
    """Start a fresh session with canonical role from credential verification."""
    session.clear()
    session["authenticated"] = True
    session["username"] = username.strip()
    session["role"] = role


def logout_user() -> None:
    session.clear()


def is_authenticated() -> bool:
    return bool(session.get("authenticated"))


def get_current_role() -> str:
    """
    Resolve role from the configured user directory (source of truth).
    Prevents stale or tampered session['role'] from elevating privileges.
    """
    if not is_authenticated():
        return Role.VIEWER.value
    username = (session.get("username") or "").strip()
    if not username:
        return Role.VIEWER.value
    directory = get_user_directory()
    entry = directory.get(username)
    if not entry:
        return Role.VIEWER.value
    role = entry[1]
    role_val = role.value if isinstance(role, Role) else str(role)
    session["role"] = role_val
    return role_val


def verify_credentials(username: str, password: str) -> Optional[str]:
    """
    Verify credentials. Returns role string on success, None on failure.
    """
    username = (username or "").strip()
    password = password or ""
    directory = get_user_directory()
    entry = directory.get(username)
    if not entry:
        return None
    expected_password, role = entry
    if password != expected_password:
        return None
    return role.value if isinstance(role, Role) else str(role)


def login_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def api_login_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authenticated():
            return jsonify({"error": "Authentication required"}), 401
        return view(*args, **kwargs)

    return wrapped


def require_permission(permission: str):
    """Require authenticated session and specific permission."""

    def decorator(view: Callable):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not is_authenticated():
                return jsonify({"error": "Authentication required"}), 401
            role = get_current_role()
            if not role_has_permission(role, permission):
                return jsonify(
                    {
                        "error": "Forbidden",
                        "message": f"Role '{role}' cannot perform: {permission}",
                    }
                ), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator
