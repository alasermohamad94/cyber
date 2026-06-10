from fastapi import APIRouter, Depends, Form, Request

from security.auth import verify_credentials
from security.config import demo_mode_enabled, env_loaded_path, get_login_display_info
from security.fastapi_auth import (
    login_user_session,
    logout_user_session,
    require_auth,
    session_info_payload,
)
from security.session_registry import get_session_registry

router = APIRouter(tags=["auth"])


@router.post("/api/login")
async def api_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    role = verify_credentials(username, password)
    if not role:
        return {
            "success": False,
            "error": "بيانات الدخول غير صحيحة",
            "accounts": get_login_display_info(),
            "env_file": env_loaded_path(),
        }
    login_user_session(request, username, role)
    session_token = request.session.get("session_id") or str(id(request.session))
    request.session["session_id"] = session_token
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    get_session_registry().register(username, role, client_ip, user_agent, session_token)
    return {"success": True, **session_info_payload(request)}


@router.post("/api/logout")
async def api_logout(request: Request):
    logout_user_session(request)
    return {"success": True}


@router.get("/api/session-info")
async def session_info(request: Request, _role: str = Depends(require_auth)):
    return {
        **session_info_payload(request),
        "demo_mode": demo_mode_enabled(),
        "demo_mode_available": demo_mode_enabled(),
    }


@router.get("/api/login-hints")
async def login_hints():
    return {
        "accounts": get_login_display_info(),
        "env_file": env_loaded_path(),
    }
