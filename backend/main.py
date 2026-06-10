"""
Cyber Defense System — FastAPI backend.
"""

import asyncio
import os
import sys

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.routes import auth, metrics, security, soc  # noqa: E402
from backend.services.monitor import format_duration, monitor  # noqa: E402
from security.config import get_bind_host, get_bind_port, get_cors_origins, get_secret_key  # noqa: E402
from security.fastapi_auth import is_authenticated  # noqa: E402
from workers.background_queue import get_background_queue  # noqa: E402

app = FastAPI(
    title="Cyber Defense System API",
    description="FastAPI backend for cyber defense monitoring and response",
    version="2.0.0",
)

app.add_middleware(
    SessionMiddleware,
    secret_key=get_secret_key(),
    same_site="lax",
    https_only=False,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(metrics.router)
app.include_router(security.router)
app.include_router(soc.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "cyber-defense-api"}


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()


@app.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    if not is_authenticated(websocket):
        await websocket.close(code=4401)
        return
    await ws_manager.connect(websocket)
    try:
        while True:
            metrics_data = monitor.get_system_metrics()
            await websocket.send_json(
                {
                    "type": "metrics_update",
                    "cpu_percent": metrics_data.cpu_percent,
                    "memory_percent": metrics_data.memory_percent,
                    "disk_usage": metrics_data.disk_usage,
                    "active_connections": metrics_data.active_connections,
                    "uptime_formatted": format_duration(metrics_data.uptime),
                    "timestamp": metrics_data.timestamp,
                }
            )
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


async def _security_alert_broadcaster():
    last_alert_count = 0
    while True:
        try:
            current = len(monitor.alerts)
            if current > last_alert_count:
                latest = monitor.alerts[-1]
                await ws_manager.broadcast(
                    {
                        "type": "security_alert",
                        "message": latest["message"],
                        "timestamp": latest["timestamp"],
                        "event_id": latest["event_id"],
                    }
                )
                last_alert_count = current
            await asyncio.sleep(5)
        except Exception:
            await asyncio.sleep(10)


async def _escalation_worker():
    from decision_engine.escalation import get_escalation_manager
    from response.engine import execute_response
    from security.firewall_providers import expire_stale_blocks

    while True:
        try:
            escalated = get_escalation_manager().check_pending_escalations()
            for item in escalated:
                execute_response(
                    item["entity_id"],
                    {
                        "action": "block",
                        "severity": "high",
                        "reasoning": item["reason"],
                    },
                )
            expire_stale_blocks()
        except Exception:
            pass
        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    get_background_queue()
    asyncio.create_task(_security_alert_broadcaster())
    asyncio.create_task(_escalation_worker())


_frontend_dist = os.path.join(PROJECT_ROOT, "frontend", "dist")
if os.path.isdir(_frontend_dist):
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=get_bind_host(),
        port=get_bind_port(),
        reload=False,
    )
