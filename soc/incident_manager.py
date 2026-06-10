"""
Security incident lifecycle management.
"""

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from decision_engine.escalation import get_escalation_manager
from security.audit_chain import get_audit_chain
from storage.persistence import get_store

INCIDENT_STATES = ("open", "investigating", "pending_approval", "resolved")
VALID_TRANSITIONS = {
    "open": {"investigating", "pending_approval", "resolved"},
    "investigating": {"pending_approval", "resolved", "open"},
    "pending_approval": {"investigating", "resolved"},
    "resolved": {"open"},
}


class IncidentManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._store = get_store()

    def create_from_correlation(
        self,
        correlation: Dict[str, Any],
        entity_id: str,
        event_ids: Optional[List[str]] = None,
        severity: str = "high",
    ) -> Dict[str, Any]:
        incident_id = correlation.get("incident_id") or f"inc_{uuid.uuid4().hex[:10]}"
        now = time.time()
        incident = {
            "incident_id": incident_id,
            "title": correlation.get("incident_type", "security_incident"),
            "incident_type": correlation.get("incident_type", "unknown"),
            "severity": correlation.get("severity", severity),
            "status": "open",
            "source_ip": correlation.get("source_ip", ""),
            "target_entity": entity_id,
            "assigned_to": "",
            "notes": correlation.get("reasoning", ""),
            "event_ids": event_ids or [],
            "created_at": now,
            "updated_at": now,
            "resolved_at": None,
        }
        with self._lock:
            self._store.save_incident(incident)
            get_audit_chain().append("incident_created", "system", incident)
        return incident

    def create_manual(
        self,
        title: str,
        severity: str,
        source_ip: str,
        target_entity: str,
        event_ids: List[str],
        created_by: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        now = time.time()
        incident = {
            "incident_id": f"inc_{uuid.uuid4().hex[:10]}",
            "title": title,
            "incident_type": "manual",
            "severity": severity,
            "status": "open",
            "source_ip": source_ip,
            "target_entity": target_entity,
            "assigned_to": created_by,
            "notes": notes,
            "event_ids": event_ids,
            "created_at": now,
            "updated_at": now,
            "resolved_at": None,
        }
        with self._lock:
            self._store.save_incident(incident)
            get_audit_chain().append("incident_created", created_by, incident)
        return incident

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        return self._store.list_incidents(
            status=status, severity=severity, assigned_to=assigned_to, limit=limit
        )

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self._store.get_incident(incident_id)

    def update_status(
        self, incident_id: str, new_status: str, actor: str, notes: str = ""
    ) -> Dict[str, Any]:
        if new_status not in INCIDENT_STATES:
            return {"success": False, "error": f"Invalid status: {new_status}"}
        with self._lock:
            incident = self._store.get_incident(incident_id)
            if not incident:
                return {"success": False, "error": "Incident not found"}
            current = incident["status"]
            if new_status not in VALID_TRANSITIONS.get(current, set()) and new_status != current:
                return {
                    "success": False,
                    "error": f"Cannot transition from {current} to {new_status}",
                }
            now = time.time()
            updates = {"status": new_status, "updated_at": now}
            if notes:
                updates["notes"] = (incident.get("notes", "") + f"\n[{actor}] {notes}").strip()
            if new_status == "resolved":
                updates["resolved_at"] = now
                get_escalation_manager().acknowledge(incident_id, actor)
            self._store.update_incident(incident_id, updates)
            get_audit_chain().append(
                "incident_status_changed",
                actor,
                {"incident_id": incident_id, "from": current, "to": new_status},
            )
            return {"success": True, "incident_id": incident_id, "status": new_status}

    def assign(self, incident_id: str, analyst: str, actor: str) -> Dict[str, Any]:
        with self._lock:
            if not self._store.get_incident(incident_id):
                return {"success": False, "error": "Incident not found"}
            self._store.update_incident(
                incident_id, {"assigned_to": analyst, "updated_at": time.time(), "status": "investigating"}
            )
            get_audit_chain().append(
                "incident_assigned", actor, {"incident_id": incident_id, "assigned_to": analyst}
            )
            return {"success": True, "assigned_to": analyst}

    def get_statistics(self) -> Dict[str, Any]:
        incidents = self._store.list_incidents(limit=500)
        stats = {s: 0 for s in INCIDENT_STATES}
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for inc in incidents:
            stats[inc.get("status", "open")] = stats.get(inc.get("status", "open"), 0) + 1
            sev = inc.get("severity", "low")
            if sev in severity_counts:
                severity_counts[sev] += 1
        return {"by_status": stats, "by_severity": severity_counts, "total": len(incidents)}


_manager: Optional[IncidentManager] = None
_manager_lock = threading.Lock()


def get_incident_manager() -> IncidentManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = IncidentManager()
        return _manager


__all__ = ["IncidentManager", "get_incident_manager", "INCIDENT_STATES"]
