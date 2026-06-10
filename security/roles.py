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
    "incidents:read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "incidents:write": {Role.ADMIN, Role.ANALYST},
    "cases:read": {Role.ADMIN, Role.ANALYST, Role.VIEWER},
    "cases:write": {Role.ADMIN, Role.ANALYST},
    "audit:verify": {Role.ADMIN, Role.ANALYST},
    "forensics:read": {Role.ADMIN, Role.ANALYST},
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


def permissions_for_role(role: str) -> list:
    """Return permission keys granted to the given role."""
    try:
        r = Role(role)
    except ValueError:
        return []
    return [perm for perm, roles in PERMISSIONS.items() if r in roles]


def role_rank(role: str) -> int:
    """Higher rank = more privileges (admin > analyst > viewer)."""
    order = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}
    try:
        return order[Role(role)]
    except ValueError:
        return -1
