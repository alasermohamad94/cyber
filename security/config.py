"""
Runtime configuration from environment variables.
"""

import os
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from security.roles import Role

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_LOADED_FROM: Optional[str] = None


def load_env_files() -> Optional[str]:
    """
    Load .env from project root and web_dashboard/ (does not override existing env vars).
    Returns path of the first file loaded, or None.
    """
    global _ENV_LOADED_FROM
    if _ENV_LOADED_FROM is not None:
        return _ENV_LOADED_FROM

    candidates = [
        _PROJECT_ROOT / ".env",
        _PROJECT_ROOT / "web_dashboard" / ".env",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        _parse_env_file(path)
        _ENV_LOADED_FROM = str(path)
        return _ENV_LOADED_FROM
    _ENV_LOADED_FROM = ""
    return None


def _parse_env_file(path: Path) -> None:
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def env_loaded_path() -> Optional[str]:
    load_env_files()
    return _ENV_LOADED_FROM or None


# Load .env before any credential reads
load_env_files()


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
    username -> (password, role). Each username must be unique or the last
    env entry would silently overwrite earlier roles (e.g. viewer gaining admin).
    """
    admin_u, admin_p = _cred("CDS_ADMIN_USER", "CDS_ADMIN_PASSWORD", "admin", "changeme")
    analyst_u, analyst_p = _cred("CDS_ANALYST_USER", "CDS_ANALYST_PASSWORD", "analyst", "analyst123")
    viewer_u, viewer_p = _cred("CDS_VIEWER_USER", "CDS_VIEWER_PASSWORD", "viewer", "viewer123")
    directory: Dict[str, Tuple[str, Role]] = {}
    for username, password, role in (
        (admin_u, admin_p, Role.ADMIN),
        (analyst_u, analyst_p, Role.ANALYST),
        (viewer_u, viewer_p, Role.VIEWER),
    ):
        key = username.strip()
        if not key:
            continue
        if key in directory:
            raise ValueError(
                f"Duplicate CDS username '{key}' in environment. "
                "Set unique CDS_ADMIN_USER, CDS_ANALYST_USER, CDS_VIEWER_USER."
            )
        directory[key] = (password, role)
    return directory


def firewall_enabled() -> bool:
    return os.environ.get("CDS_FIREWALL_ENABLED", "true").lower() in ("1", "true", "yes")


def demo_mode_enabled() -> bool:
    return os.environ.get("CDS_DEMO_MODE", "false").lower() in ("1", "true", "yes")


def get_login_display_info() -> List[Dict[str, str]]:
    """Usernames and password hints for the login page (no secrets in production logs)."""
    admin_u, admin_p = _cred("CDS_ADMIN_USER", "CDS_ADMIN_PASSWORD", "admin", "changeme")
    analyst_u, analyst_p = _cred("CDS_ANALYST_USER", "CDS_ANALYST_PASSWORD", "analyst", "analyst123")
    viewer_u, viewer_p = _cred("CDS_VIEWER_USER", "CDS_VIEWER_PASSWORD", "viewer", "viewer123")

    def _hint(user_key: str, pass_key: str, default_pass: str, current: str) -> str:
        if os.environ.get(pass_key):
            return f"من {pass_key} في البيئة"
        if os.environ.get(user_key):
            return f"افتراضي: {default_pass}"
        return default_pass

    return [
        {
            "username": admin_u,
            "role_label": "مدير",
            "password_hint": _hint("CDS_ADMIN_USER", "CDS_ADMIN_PASSWORD", "changeme", admin_p),
        },
        {
            "username": analyst_u,
            "role_label": "محلل",
            "password_hint": _hint("CDS_ANALYST_USER", "CDS_ANALYST_PASSWORD", "analyst123", analyst_p),
        },
        {
            "username": viewer_u,
            "role_label": "مشاهدة",
            "password_hint": _hint("CDS_VIEWER_USER", "CDS_VIEWER_PASSWORD", "viewer123", viewer_p),
        },
    ]
