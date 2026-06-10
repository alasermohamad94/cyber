"""
Security case management for multi-incident investigations.
"""

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from security.audit_chain import get_audit_chain
from storage.persistence import get_store


class CaseManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._store = get_store()

    def create_case(
        self,
        title: str,
        description: str,
        created_by: str,
        incident_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        case_id = f"case_{uuid.uuid4().hex[:10]}"
        now = time.time()
        case = {
            "case_id": case_id,
            "title": title,
            "description": description,
            "status": "open",
            "created_by": created_by,
            "assigned_to": created_by,
            "incident_ids": incident_ids or [],
            "entity_ids": [],
            "ip_addresses": [],
            "investigator_notes": "",
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            self._store.save_case(case)
            get_audit_chain().append("case_created", created_by, {"case_id": case_id, "title": title})
        return case

    def merge_incidents(self, case_id: str, incident_ids: List[str], actor: str) -> Dict[str, Any]:
        with self._lock:
            case = self._store.get_case(case_id)
            if not case:
                return {"success": False, "error": "Case not found"}
            merged = list(set(case.get("incident_ids", []) + incident_ids))
            entity_ids = set(case.get("entity_ids", []))
            ip_addresses = set(case.get("ip_addresses", []))
            for iid in incident_ids:
                inc = self._store.get_incident(iid)
                if inc:
                    if inc.get("target_entity"):
                        entity_ids.add(inc["target_entity"])
                    if inc.get("source_ip"):
                        ip_addresses.add(inc["source_ip"])
            self._store.update_case(
                case_id,
                {
                    "incident_ids": merged,
                    "entity_ids": list(entity_ids),
                    "ip_addresses": list(ip_addresses),
                    "updated_at": time.time(),
                },
            )
            get_audit_chain().append(
                "case_incidents_merged", actor, {"case_id": case_id, "incident_ids": incident_ids}
            )
            return {"success": True, "case_id": case_id, "incident_count": len(merged)}

    def add_note(self, case_id: str, note: str, author: str) -> Dict[str, Any]:
        with self._lock:
            case = self._store.get_case(case_id)
            if not case:
                return {"success": False, "error": "Case not found"}
            notes = case.get("investigator_notes", "")
            entry = f"\n[{author} @ {time.strftime('%Y-%m-%d %H:%M')}] {note}"
            self._store.update_case(
                case_id, {"investigator_notes": (notes + entry).strip(), "updated_at": time.time()}
            )
            return {"success": True}

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        case = self._store.get_case(case_id)
        if not case:
            return None
        incidents = []
        for iid in case.get("incident_ids", []):
            inc = self._store.get_incident(iid)
            if inc:
                incidents.append(inc)
        case["linked_incidents"] = incidents
        return case

    def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._store.list_cases(limit=limit)

    def get_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        case = self.get_case(case_id)
        if not case:
            return []
        events = []
        for inc in case.get("linked_incidents", []):
            for eid in inc.get("event_ids", []):
                ev = self._store.get_security_event(eid)
                if ev:
                    events.append(ev)
        events.sort(key=lambda e: e.get("timestamp", 0))
        return events


_manager: Optional[CaseManager] = None
_manager_lock = threading.Lock()


def get_case_manager() -> CaseManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = CaseManager()
        return _manager


__all__ = ["CaseManager", "get_case_manager"]
