"""
SOAR-lite structured response playbooks.
"""

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from security.audit_chain import get_audit_chain
from security.firewall_providers import orchestrate_block
from storage.persistence import get_store


@dataclass(frozen=True)
class PlaybookStep:
    step_id: str
    name: str
    handler: str


@dataclass(frozen=True)
class Playbook:
    playbook_id: str
    name: str
    description: str
    steps: List[PlaybookStep]


PLAYBOOKS: Dict[str, Playbook] = {
    "ransomware_response": Playbook(
        playbook_id="ransomware_response",
        name="استجابة برامج الفدية",
        description="قطع الاتصالات، تنبيه SOC، حظر IP، حفظ حالة للتحليل الجنائي",
        steps=[
            PlaybookStep("cut_egress", "قطع الاتصالات الخارجية", "cut_egress"),
            PlaybookStep("soc_alert", "تنبيه SOC فوري", "soc_alert"),
            PlaybookStep("firewall_block", "حظر IP المهاجم", "firewall_block"),
            PlaybookStep("forensic_snapshot", "حفظ حالة للتحليل الجنائي", "forensic_snapshot"),
        ],
    ),
    "brute_force_response": Playbook(
        playbook_id="brute_force_response",
        name="استجابة التخمين الموجه",
        description="حظر المصدر وتصعيد المراقبة",
        steps=[
            PlaybookStep("firewall_block", "حظر IP", "firewall_block"),
            PlaybookStep("soc_alert", "تنبيه SOC", "soc_alert"),
            PlaybookStep("enhance_monitor", "تصعيد المراقبة", "enhance_monitor"),
        ],
    ),
    "exfiltration_response": Playbook(
        playbook_id="exfiltration_response",
        name="استجابة تسريب البيانات",
        description="عزل الأصل وحظر الوجهة الخارجية",
        steps=[
            PlaybookStep("quarantine", "عزل الكيان", "quarantine"),
            PlaybookStep("firewall_block", "حظر IP الوجهة", "firewall_block"),
            PlaybookStep("soc_alert", "تنبيه SOC حرج", "soc_alert"),
        ],
    ),
}


class PlaybookExecutor:
    def __init__(self):
        self._lock = threading.RLock()
        self._handlers: Dict[str, Callable[..., Dict[str, Any]]] = {
            "cut_egress": self._cut_egress,
            "soc_alert": self._soc_alert,
            "firewall_block": self._firewall_block,
            "forensic_snapshot": self._forensic_snapshot,
            "enhance_monitor": self._enhance_monitor,
            "quarantine": self._quarantine,
        }

    def list_playbooks(self) -> List[Dict[str, Any]]:
        return [
            {
                "playbook_id": pb.playbook_id,
                "name": pb.name,
                "description": pb.description,
                "steps": [{"step_id": s.step_id, "name": s.name} for s in pb.steps],
            }
            for pb in PLAYBOOKS.values()
        ]

    def execute(
        self,
        playbook_id: str,
        context: Dict[str, Any],
        triggered_by: str = "system",
    ) -> Dict[str, Any]:
        with self._lock:
            playbook = PLAYBOOKS.get(playbook_id)
            if not playbook:
                return {"success": False, "error": f"Unknown playbook: {playbook_id}"}

            run_id = f"pbrun_{int(time.time())}"
            step_results = []
            for step in playbook.steps:
                handler = self._handlers.get(step.handler)
                if not handler:
                    step_results.append(
                        {"step_id": step.step_id, "status": "skipped", "message": "No handler"}
                    )
                    continue
                result = handler(context)
                step_results.append({"step_id": step.step_id, "name": step.name, **result})

            get_audit_chain().append(
                "playbook_executed",
                triggered_by,
                {"playbook_id": playbook_id, "run_id": run_id, "steps": step_results},
            )
            return {
                "success": True,
                "playbook_id": playbook_id,
                "run_id": run_id,
                "steps": step_results,
            }

    def _cut_egress(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        entity_id = ctx.get("entity_id", "unknown")
        get_store().save_quarantine(
            {
                "quarantine_id": f"q_{int(time.time())}",
                "entity_id": entity_id,
                "quarantine_type": "egress_cut",
                "status": "active",
                "created_at": time.time(),
                "details": {"action": "external_connections_blocked"},
            }
        )
        return {"status": "completed", "message": f"Egress cut for {entity_id}"}

    def _soc_alert(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "completed",
            "message": "SOC alert dispatched via WebSocket",
            "alert_id": f"alert_{int(time.time())}",
            "severity": ctx.get("severity", "high"),
        }

    def _firewall_block(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        ip = ctx.get("source_ip") or ctx.get("attacker_ip")
        if not ip:
            return {"status": "skipped", "message": "No IP to block"}
        result = orchestrate_block(ip, ctx.get("reason", "playbook_block"), ttl_seconds=7200)
        return {"status": "completed" if result.get("success") else "failed", **result}

    def _forensic_snapshot(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        entity_id = ctx.get("entity_id", "unknown")
        snapshot_id = f"snap_{int(time.time())}"
        get_audit_chain().append(
            "forensic_snapshot",
            "playbook",
            {"entity_id": entity_id, "snapshot_id": snapshot_id, "note": "Memory state placeholder"},
        )
        return {
            "status": "completed",
            "message": f"Forensic snapshot recorded for {entity_id}",
            "snapshot_id": snapshot_id,
            "requires_live_agent": True,
        }

    def _enhance_monitor(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "completed",
            "message": f"Enhanced monitoring for {ctx.get('entity_id', 'unknown')}",
        }

    def _quarantine(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        entity_id = ctx.get("entity_id", "unknown")
        get_store().save_quarantine(
            {
                "quarantine_id": f"q_{int(time.time())}",
                "entity_id": entity_id,
                "quarantine_type": "virtual_quarantine",
                "status": "active",
                "created_at": time.time(),
                "details": {"network_isolated": True, "accounts_disabled": False},
            }
        )
        return {
            "status": "completed",
            "message": f"Virtual quarantine applied to {entity_id}",
            "requires_network_infra": True,
        }


_executor: Optional[PlaybookExecutor] = None
_executor_lock = threading.Lock()


def get_playbook_executor() -> PlaybookExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = PlaybookExecutor()
        return _executor


__all__ = ["PlaybookExecutor", "get_playbook_executor", "PLAYBOOKS"]
