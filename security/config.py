"""
Runtime configuration from environment variables.
"""

import os
import secrets
from typing import Dict, Tuple

from security.roles import Role


def get_secret_key() -> str:
    key = os.environ.get("CDS_SECRET_KEY")
    if not key:
        key = secrets.token_hex(32)
        os.environ["CDS_SECRET_KEY"] = key
    return key


def get_bind_host() -> str:
    return os.environ.get("CDS_BIND_HOST", "127.0.0.1")


def get_bind_port() -> int:
    return int(os.environ.get("CDS_PORT", os.environ.get("PORT", "8080")))


def get_cors_origins() -> list:
    raw = os.environ.get("CDS_CORS_ORIGINS", "http://127.0.0.1:8080,http://localhost:8080")
    return [o.strip() for o in raw.split(",") if o.strip()]


def _cred(env_user: str, env_pass: str, default_user: str, default_pass: str) -> Tuple[str, str]:
    return (
        os.environ.get(env_user, default_user),
        os.environ.get(env_pass, default_pass),
    )


def get_user_directory() -> Dict[str, Tuple[str, Role]]:
    """
    username -> (password, role)
    """
    admin_u, admin_p = _cred("CDS_ADMIN_USER", "CDS_ADMIN_PASSWORD", "admin", "changeme")
    analyst_u, analyst_p = _cred("CDS_ANALYST_USER", "CDS_ANALYST_PASSWORD", "analyst", "analyst123")
    viewer_u, viewer_p = _cred("CDS_VIEWER_USER", "CDS_VIEWER_PASSWORD", "viewer", "viewer123")
    return {
        admin_u: (admin_p, Role.ADMIN),
        analyst_u: (analyst_p, Role.ANALYST),
        viewer_u: (viewer_p, Role.VIEWER),
    }


def firewall_enabled() -> bool:
    return os.environ.get("CDS_FIREWALL_ENABLED", "true").lower() in ("1", "true", "yes")


def demo_mode_enabled() -> bool:
    return os.environ.get("CDS_DEMO_MODE", "false").lower() in ("1", "true", "yes")
