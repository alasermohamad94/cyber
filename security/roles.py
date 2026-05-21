"""
Role-based access control for the web dashboard.
"""

from enum import Enum
from typing import Dict, Optional, Set, Tuple


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Permission → allowed roles
PERMISSIONS: Dict[str, Set[Role]] = {
    "metrics:read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "security:read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "entity:analyze": {Role.ADMIN, Role.ANALYST},
    "ip:block": {Role.ADMIN},
    "ip:unblock": {Role.ADMIN},
    "report:generate": {Role.ADMIN, Role.ANALYST},
    "settings:write": {Role.ADMIN},
}


def role_has_permission(role: str, permission: str) -> bool:
    allowed = PERMISSIONS.get(permission, set())
    try:
        return Role(role) in allowed
    except ValueError:
        return False


def resolve_role_for_user(username: str, credential_map: Dict[str, Tuple[str, Role]]) -> Optional[Role]:
    entry = credential_map.get(username)
    if entry:
        return entry[1]
    return None
