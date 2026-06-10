"""
Active session tracking and revocation for SOC governance.
"""

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from storage.persistence import get_store


class SessionRegistry:
    def __init__(self):
        self._lock = threading.RLock()

    @property
    def _store(self):
        return get_store()

    def register(
        self,
        username: str,
        role: str,
        ip_address: str,
        user_agent: str,
        session_token: str,
    ) -> str:
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        now = time.time()
        record = {
            "session_id": session_id,
            "username": username,
            "role": role,
            "ip_address": ip_address,
            "user_agent": user_agent[:256],
            "session_token": session_token,
            "created_at": now,
            "last_activity": now,
            "status": "active",
        }
        with self._lock:
            self._store.save_active_session(record)
        return session_id

    def touch(self, session_token: str) -> None:
        with self._lock:
            self._store.update_session_activity(session_token, time.time())

    def list_active(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._store.list_active_sessions()

    def revoke(self, session_id: str, revoked_by: str) -> bool:
        with self._lock:
            return self._store.revoke_session(session_id, revoked_by, time.time())

    def is_revoked(self, session_token: str) -> bool:
        with self._lock:
            return self._store.is_session_revoked(session_token)


_registry: Optional[SessionRegistry] = None
_registry_lock = threading.Lock()


def get_session_registry() -> SessionRegistry:
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = SessionRegistry()
        return _registry


__all__ = ["SessionRegistry", "get_session_registry"]
