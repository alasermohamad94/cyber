"""
SOC platform API routes: incidents, cases, audit, playbooks, approvals, sessions.
"""

import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from backend.services.monitor import monitor, serialize_events
from decision_engine.escalation import get_escalation_manager
from decision_engine.security_policies import requires_two_man_approval
from response.playbooks import get_playbook_executor
from security.audit_chain import get_audit_chain
from security.fastapi_auth import require_permission_dep, session_info_payload
from security.firewall_providers import expire_stale_blocks, list_providers, orchestrate_block
from security.session_registry import get_session_registry
from soc.case_manager import get_case_manager
from soc.incident_manager import get_incident_manager
from storage.persistence import get_store
from storage.query_engine import query_events, replay_events
from trust_system.trust_manager import get_all_trust_records, get_trust_record

router = APIRouter(tags=["soc"])


class CreateIncidentBody(BaseModel):
    title: str
    severity: str = "medium"
    source_ip: str = ""
    target_entity: str = ""
    event_ids: List[str] = []
    notes: str = ""


class UpdateIncidentBody(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: str = ""


class CreateCaseBody(BaseModel):
    title: str
    description: str = ""
    incident_ids: List[str] = []


class MergeIncidentsBody(BaseModel):
    incident_ids: List[str]


class CaseNoteBody(BaseModel):
    note: str


class QueryEventsBody(BaseModel):
    filters: Dict[str, Any] = {}
    logic: str = "and"
    limit: int = 100
    offset: int = 0


class ReplayBody(BaseModel):
    entity_id: Optional[str] = None
    source_ip: Optional[str] = None
    since: Optional[float] = None
    until: Optional[float] = None


class PlaybookBody(BaseModel):
    playbook_id: str
    context: Dict[str, Any] = {}


class BlockIpBody(BaseModel):
    ip_address: str
    reason: str = "manual_block"
    provider: str = "local_os"
    ttl_seconds: int = 3600


class ApprovalBody(BaseModel):
    approval_id: str
    is_second: bool = False


class SensitiveActionBody(BaseModel):
    action_type: str
    target_entity: str = ""
    target_ip: str = ""
    password_confirm: str = ""
    justification: str = ""
    details: Dict[str, Any] = {}


class TrustRecoveryBody(BaseModel):
    entity_id: str
    note: str = ""


@router.get("/api/soc/command-center")
async def soc_command_center(_role: str = Depends(require_permission_dep("security:read"))):
    """Unified SOC dashboard statistics."""
    store = get_store()
    inc_stats = get_incident_manager().get_statistics()
    trust_records = get_all_trust_records()
    events = store.list_security_events(limit=200)
    now = time.time()
    day_ago = now - 86400

    ip_counts: Dict[str, int] = {}
    entity_targets: Dict[str, int] = {}
    for ev in events:
        if ev.get("timestamp", 0) >= day_ago:
            sip = ev.get("source_ip", "")
            if sip:
                ip_counts[sip] = ip_counts.get(sip, 0) + 1
            te = ev.get("target_entity", "")
            if te:
                entity_targets[te] = entity_targets.get(te, 0) + 1

    critical_count = sum(1 for e in events if e.get("severity") == "critical")
    high_count = sum(1 for e in events if e.get("severity") == "high")
    threat_level = "low"
    if critical_count >= 3:
        threat_level = "critical"
    elif critical_count >= 1 or high_count >= 5:
        threat_level = "high"
    elif high_count >= 1:
        threat_level = "medium"

    audit_status = get_audit_chain().verify_chain(limit=200)

    return {
        "threat_level": threat_level,
        "incident_stats": inc_stats,
        "trust_summary": {
            "total_entities": len(trust_records),
            "high_risk": sum(1 for r in trust_records if r.get("risk_level") in ("high", "critical")),
        },
        "geo_distribution": [{"ip": ip, "count": c} for ip, c in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]],
        "top_targeted_entities": [
            {"entity_id": e, "event_count": c}
            for e, c in sorted(entity_targets.items(), key=lambda x: -x[1])[:10]
        ],
        "audit_chain_valid": audit_status.get("valid", False),
        "active_quarantine": len(store.list_quarantine(active_only=True)),
        "pending_approvals": len(store.list_pending_approvals()),
        "recent_events": serialize_events(monitor, 15),
    }


@router.get("/api/incidents")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    _role: str = Depends(require_permission_dep("incidents:read")),
):
    return {"incidents": get_incident_manager().list_incidents(status=status, severity=severity)}


@router.get("/api/incidents/{incident_id}")
async def get_incident_detail(
    incident_id: str,
    _role: str = Depends(require_permission_dep("incidents:read")),
):
    inc = get_incident_manager().get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    store = get_store()
    linked_events = []
    for eid in inc.get("event_ids", []):
        ev = store.get_security_event(eid)
        if ev:
            linked_events.append(ev)
    inc["linked_events"] = linked_events
    return inc


@router.post("/api/incidents")
async def create_incident(
    body: CreateIncidentBody,
    request: Request,
    _role: str = Depends(require_permission_dep("incidents:write")),
):
    username = request.session.get("username", "analyst")
    inc = get_incident_manager().create_manual(
        title=body.title,
        severity=body.severity,
        source_ip=body.source_ip,
        target_entity=body.target_entity,
        event_ids=body.event_ids,
        created_by=username,
        notes=body.notes,
    )
    return inc


@router.patch("/api/incidents/{incident_id}")
async def update_incident(
    incident_id: str,
    body: UpdateIncidentBody,
    request: Request,
    _role: str = Depends(require_permission_dep("incidents:write")),
):
    username = request.session.get("username", "analyst")
    mgr = get_incident_manager()
    if body.assigned_to:
        mgr.assign(incident_id, body.assigned_to, username)
    if body.status:
        result = mgr.update_status(incident_id, body.status, username, body.notes)
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error"))
    return mgr.get_incident(incident_id)


@router.get("/api/cases")
async def list_cases(_role: str = Depends(require_permission_dep("cases:read"))):
    return {"cases": get_case_manager().list_cases()}


@router.post("/api/cases")
async def create_case(
    body: CreateCaseBody,
    request: Request,
    _role: str = Depends(require_permission_dep("cases:write")),
):
    username = request.session.get("username", "analyst")
    return get_case_manager().create_case(
        body.title, body.description, username, body.incident_ids
    )


@router.get("/api/cases/{case_id}")
async def get_case_detail(
    case_id: str,
    _role: str = Depends(require_permission_dep("cases:read")),
):
    case = get_case_manager().get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case["timeline"] = get_case_manager().get_timeline(case_id)
    return case


@router.post("/api/cases/{case_id}/merge")
async def merge_incidents_to_case(
    case_id: str,
    body: MergeIncidentsBody,
    request: Request,
    _role: str = Depends(require_permission_dep("cases:write")),
):
    username = request.session.get("username", "analyst")
    result = get_case_manager().merge_incidents(case_id, body.incident_ids, username)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/api/cases/{case_id}/notes")
async def add_case_note(
    case_id: str,
    body: CaseNoteBody,
    request: Request,
    _role: str = Depends(require_permission_dep("cases:write")),
):
    username = request.session.get("username", "analyst")
    result = get_case_manager().add_note(case_id, body.note, username)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/api/events/query")
async def query_security_events(
    body: QueryEventsBody,
    _role: str = Depends(require_permission_dep("security:read")),
):
    return query_events(body.filters, body.logic, body.limit, body.offset)


@router.post("/api/forensics/replay")
async def forensic_replay(
    body: ReplayBody,
    _role: str = Depends(require_permission_dep("audit:verify")),
):
    return replay_events(body.entity_id, body.since, body.until, body.source_ip)


@router.get("/api/audit/verify")
async def verify_audit_chain(_role: str = Depends(require_permission_dep("audit:verify"))):
    result = get_audit_chain().verify_chain(limit=500)
    if not result.get("valid"):
        monitor.add_security_event(
            event_type="audit_tamper_detected",
            severity="critical",
            source_ip="system",
            target_entity="audit_log_chain",
            description=f"Audit chain integrity broken at {result.get('broken_at')}",
            action_taken="alert",
        )
    return result


@router.get("/api/audit/records")
async def list_audit_records(
    limit: int = 50,
    _role: str = Depends(require_permission_dep("audit:verify")),
):
    return {"records": get_audit_chain().query(limit=limit)}


@router.get("/api/playbooks")
async def list_playbooks(_role: str = Depends(require_permission_dep("security:read"))):
    return {"playbooks": get_playbook_executor().list_playbooks()}


@router.post("/api/playbooks/execute")
async def execute_playbook(
    body: PlaybookBody,
    request: Request,
    _role: str = Depends(require_permission_dep("playbook:trigger")),
):
    username = request.session.get("username", "analyst")
    ctx = {**body.context, "triggered_by": username}
    return get_playbook_executor().execute(body.playbook_id, ctx, triggered_by=username)


@router.get("/api/firewall/providers")
async def firewall_providers(_role: str = Depends(require_permission_dep("security:read"))):
    return {"providers": list_providers()}


@router.post("/api/firewall/block")
async def block_ip_orchestrated(
    body: BlockIpBody,
    request: Request,
    _role: str = Depends(require_permission_dep("ip:block")),
):
    username = request.session.get("username", "admin")
    result = orchestrate_block(body.ip_address, body.reason, body.provider, body.ttl_seconds)
    get_audit_chain().append("ip_blocked", username, result)
    monitor.add_security_event(
        event_type="ip_blocked",
        severity="medium",
        source_ip=body.ip_address,
        target_entity="firewall",
        description=f"IP blocked via {body.provider}: {body.reason}",
        action_taken="blocked",
    )
    return result


@router.get("/api/quarantine")
async def list_quarantine(_role: str = Depends(require_permission_dep("quarantine:manage"))):
    return {"quarantine": get_store().list_quarantine(active_only=True)}


@router.post("/api/quarantine/{quarantine_id}/release")
async def release_quarantine(
    quarantine_id: str,
    request: Request,
    _role: str = Depends(require_permission_dep("quarantine:manage")),
):
    username = request.session.get("username", "admin")
    released = get_store().release_quarantine(quarantine_id)
    if not released:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    get_audit_chain().append("quarantine_released", username, {"quarantine_id": quarantine_id})
    return {"success": True}


@router.get("/api/approvals/pending")
async def list_pending_approvals(_role: str = Depends(require_permission_dep("approvals:manage"))):
    return {"approvals": get_store().list_pending_approvals()}


@router.post("/api/approvals/approve")
async def approve_pending_action(
    body: ApprovalBody,
    request: Request,
    _role: str = Depends(require_permission_dep("approvals:manage")),
):
    username = request.session.get("username", "admin")
    result = get_store().approve_action(body.approval_id, username, body.is_second)
    if not result:
        raise HTTPException(status_code=404, detail="Approval not found")
    get_audit_chain().append("approval_granted", username, {"approval_id": body.approval_id})
    return result


@router.post("/api/approvals/request")
async def request_sensitive_approval(
    body: SensitiveActionBody,
    request: Request,
    _role: str = Depends(require_permission_dep("entity:analyze")),
):
    username = request.session.get("username", "analyst")
    if not body.justification.strip():
        raise HTTPException(status_code=400, detail="Security justification required")
    approval = {
        "approval_id": f"appr_{uuid.uuid4().hex[:10]}",
        "action_type": body.action_type,
        "target_entity": body.target_entity,
        "target_ip": body.target_ip,
        "requested_by": username,
        "status": "pending",
        "details": {**body.details, "justification": body.justification},
        "created_at": time.time(),
    }
    get_store().save_pending_approval(approval)
    incident_id = body.details.get("incident_id")
    if incident_id:
        get_incident_manager().update_status(str(incident_id), "pending_approval", username)
    return approval


@router.get("/api/sessions")
async def list_sessions(_role: str = Depends(require_permission_dep("sessions:manage"))):
    sessions = get_session_registry().list_active()
    for s in sessions:
        s["created_at_formatted"] = datetime.fromtimestamp(s["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        s["last_activity_formatted"] = datetime.fromtimestamp(s["last_activity"]).strftime("%Y-%m-%d %H:%M:%S")
    return {"sessions": sessions}


@router.post("/api/sessions/{session_id}/revoke")
async def revoke_session(
    session_id: str,
    request: Request,
    _role: str = Depends(require_permission_dep("sessions:manage")),
):
    username = request.session.get("username", "admin")
    ok = get_session_registry().revoke(session_id, username)
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found")
    get_audit_chain().append("session_revoked", username, {"session_id": session_id})
    return {"success": True}


@router.get("/api/entities/trust")
async def entity_trust_center(_role: str = Depends(require_permission_dep("security:read"))):
    records = get_all_trust_records()
    enriched = []
    for r in records:
        enriched.append({
            **r,
            "asset_label": {
                "employee_device": "جهاز موظف",
                "web_server": "خادم ويب",
                "database_server": "خادم قاعدة بيانات",
            }.get(r.get("asset_type", ""), r.get("asset_type")),
        })
    return {"entities": enriched}


@router.post("/api/entities/trust/recover")
async def manual_trust_recovery(
    body: TrustRecoveryBody,
    request: Request,
    _role: str = Depends(require_permission_dep("incidents:write")),
):
    from trust_system.trust_manager import _trust_manager

    username = request.session.get("username", "analyst")
    ok = _trust_manager.manual_trust_recovery(body.entity_id, username, body.note)
    if not ok:
        raise HTTPException(status_code=404, detail="Entity not found")
    return {"success": True, "entity_id": body.entity_id}


@router.get("/api/soc/realtime-events")
async def realtime_events(_role: str = Depends(require_permission_dep("security:read"))):
    return {"events": serialize_events(monitor, 50), "alerts": list(monitor.alerts)[-20:]}


@router.post("/api/incidents/from-event/{event_id}")
async def create_incident_from_event(
    event_id: str,
    request: Request,
    _role: str = Depends(require_permission_dep("incidents:write")),
):
    """One-click investigation: create incident from security event."""
    store = get_store()
    ev = store.get_security_event(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    username = request.session.get("username", "analyst")
    inc = get_incident_manager().create_manual(
        title=f"حادثة من حدث {ev.get('event_type', '')}",
        severity=ev.get("severity", "medium"),
        source_ip=ev.get("source_ip", ""),
        target_entity=ev.get("target_entity", ""),
        event_ids=[event_id],
        created_by=username,
        notes=ev.get("description", ""),
    )
    return inc
