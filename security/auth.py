"""
Credential verification for the Cyber Defense System API.
"""

from typing import Optional

from security.config import get_user_directory
from security.roles import Role


def verify_credentials(username: str, password: str) -> Optional[str]:
    """Verify credentials. Returns role string on success, None on failure."""
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
