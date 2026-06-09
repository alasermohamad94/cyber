"""
Session-based authentication for FastAPI (Starlette sessions).
"""

from fastapi import Depends, HTTPException, Request, status
from starlette.requests import HTTPConnection

from security.config import get_user_directory
from security.roles import Role, permissions_for_role, role_has_permission


def _session(request: Request) -> dict:
    return request.session


def login_user_session(request: Request, username: str, role: str) -> None:
    request.session.clear()
    request.session["authenticated"] = True
    request.session["username"] = username.strip()
    request.session["role"] = role


def logout_user_session(request: Request) -> None:
    request.session.clear()


def is_authenticated(conn: HTTPConnection) -> bool:
    return bool(conn.session.get("authenticated"))


def get_current_role(request: Request) -> str:
    if not is_authenticated(request):
        return Role.VIEWER.value
    username = (request.session.get("username") or "").strip()
    if not username:
        return Role.VIEWER.value
    directory = get_user_directory()
    entry = directory.get(username)
    if not entry:
        return Role.VIEWER.value
    role = entry[1]
    role_val = role.value if isinstance(role, Role) else str(role)
    request.session["role"] = role_val
    return role_val


def require_auth(request: Request) -> str:
    if not is_authenticated(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return get_current_role(request)


def require_permission_dep(permission: str):
    def dependency(request: Request, _role: str = Depends(require_auth)) -> str:
        role = get_current_role(request)
        if not role_has_permission(role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Forbidden",
                    "message": f"Role '{role}' cannot perform: {permission}",
                },
            )
        return role

    return dependency


def session_info_payload(request: Request) -> dict:
    role = get_current_role(request)
    return {
        "username": request.session.get("username"),
        "role": role,
        "permissions": permissions_for_role(role) if role else [],
    }
