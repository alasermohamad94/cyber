"""
Auto-escalation: alert → block after 10 minutes if analyst has not closed the alert.
"""

import threading
import time
from typing import Any, Dict, List, Optional

from storage.persistence import get_store

ESCALATION_WINDOW_SECONDS = 600  # 10 minutes


class EscalationManager:
    def __init__(self):
        self._lock = threading.RLock()

    @property
    def _store(self):
        from storage.persistence import get_store

        return get_store()

    def register_alert(self, entity_id: str, incident_id: str, action: str) -> None:
        if action != "alert":
            return
        with self._lock:
            self._store.save_escalation_watch(
                {
                    "watch_id": f"esc_{incident_id}",
                    "entity_id": entity_id,
                    "incident_id": incident_id,
                    "original_action": action,
                    "created_at": time.time(),
                    "escalate_at": time.time() + ESCALATION_WINDOW_SECONDS,
                    "status": "watching",
                }
            )

    def acknowledge(self, incident_id: str, analyst: str) -> bool:
        with self._lock:
            return self._store.resolve_escalation_watch(incident_id, analyst, time.time())

    def check_pending_escalations(self) -> List[Dict[str, Any]]:
        with self._lock:
            now = time.time()
            due = self._store.list_due_escalations(now)
            escalated = []
            for watch in due:
                self._store.mark_escalation_triggered(watch["watch_id"], now)
                escalated.append(
                    {
                        "watch_id": watch["watch_id"],
                        "entity_id": watch["entity_id"],
                        "incident_id": watch["incident_id"],
                        "escalated_action": "block",
                        "reason": "Auto-escalation: alert not acknowledged within 10 minutes",
                    }
                )
            return escalated


_manager: Optional[EscalationManager] = None
_manager_lock = threading.Lock()


def get_escalation_manager() -> EscalationManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = EscalationManager()
        return _manager


__all__ = ["EscalationManager", "get_escalation_manager", "ESCALATION_WINDOW_SECONDS"]
