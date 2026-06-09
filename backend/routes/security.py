import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.services.monitor import monitor, serialize_events
from response.engine import (
    execute_response,
    get_active_responses,
    get_recent_responses,
    get_response_summary,
)
from security.fastapi_auth import require_permission_dep
from security.firewall import apply_firewall_block, remove_firewall_block, validate_ip
from storage.persistence import get_store
from trust_system.trust_manager import get_all_trust_records, get_trust_statistics
from backend.metrics_contract import data_quality_payload

router = APIRouter(tags=["security"])


class AnalyzeEntityBody(BaseModel):
    entity_id: str
    entity_data: dict = {}


class IpActionBody(BaseModel):
    ip_address: str
    reason: str = "manual_block"


@router.get("/api/security-overview")
async def get_security_overview(_role: str = Depends(require_permission_dep("security:read"))):
    return {
        "trust_statistics": get_trust_statistics(),
        "active_responses": get_active_responses(),
        "recent_responses": get_recent_responses(10),
        "response_summary": get_response_summary(),
        "total_events": len(monitor.security_events),
        "active_alerts": len(monitor.alerts),
        "recent_events": serialize_events(monitor, 10),
        "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
    }


@router.get("/api/threat-overview")
async def get_threat_overview(_role: str = Depends(require_permission_dep("security:read"))):
    high_events = [
        e for e in get_store().list_security_events(50)
        if e["severity"] in ("high", "critical")
    ]
    blocked = get_store().list_blocked_ips(active_only=True)
    resp_summary = get_response_summary()
    risk_dist = get_trust_statistics().get("risk_distribution", {})
    return {
        "active_threats": len(high_events),
        "blocked_ips_count": len(blocked),
        "blocked_ips": blocked,
        "isolated_systems": resp_summary.get("isolated_systems", 0),
        "resolved_today": resp_summary.get("resolved_today", 0),
        "active_responses": get_active_responses(),
        "recent_responses": get_recent_responses(15),
        "high_risk_events": high_events,
        "risk_distribution": risk_dist,
        "timeline": serialize_events(monitor, 15),
        "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
    }


@router.get("/api/blocked-ips")
async def list_blocked_ips(_role: str = Depends(require_permission_dep("security:read"))):
    rows = get_store().list_blocked_ips(active_only=True)
    for row in rows:
        row["blocked_at_formatted"] = datetime.fromtimestamp(row["blocked_at"]).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    return {"blocked_ips": rows, "count": len(rows)}


@router.post("/api/analyze-entity")
async def analyze_entity(
    body: AnalyzeEntityBody,
    _role: str = Depends(require_permission_dep("entity:analyze")),
):
    result = monitor.analyze_entity(body.entity_id, body.entity_data)
    if "decision" in result:
        execute_response(body.entity_id, result["decision"])
    return result


@router.post("/api/block-ip")
async def block_ip(
    body: IpActionBody,
    _role: str = Depends(require_permission_dep("ip:block")),
):
    if not validate_ip(body.ip_address):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    applied, fw_message = apply_firewall_block(body.ip_address)
    get_store().save_blocked_ip(body.ip_address, body.reason, applied)
    monitor.add_security_event(
        event_type="ip_blocked",
        severity="medium",
        source_ip=body.ip_address,
        target_entity="firewall",
        description=f"IP {body.ip_address} blocked ({body.reason})",
        action_taken="blocked" if applied else "policy_recorded",
    )
    return {
        "success": True,
        "firewall_applied": applied,
        "message": fw_message,
        "ip_address": body.ip_address,
    }


@router.post("/api/unblock-ip")
async def unblock_ip(
    body: IpActionBody,
    _role: str = Depends(require_permission_dep("ip:unblock")),
):
    if not validate_ip(body.ip_address):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    removed, fw_message = remove_firewall_block(body.ip_address)
    released = get_store().unblock_ip(body.ip_address)
    if not released and not removed:
        raise HTTPException(status_code=404, detail="IP not found in block list")
    monitor.add_security_event(
        event_type="ip_unblocked",
        severity="low",
        source_ip=body.ip_address,
        target_entity="firewall",
        description=f"IP {body.ip_address} unblocked",
        action_taken="unblocked",
    )
    return {"success": True, "message": fw_message}


@router.get("/api/security-report")
async def get_security_report(_role: str = Depends(require_permission_dep("report:generate"))):
    trust_stats = get_trust_statistics()
    trust_records = get_all_trust_records()
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "executive_summary": {
            "total_entities": len(trust_records),
            "active_responses": len(get_active_responses()),
            "recent_responses": len(get_recent_responses(20)),
            "total_events": len(monitor.security_events),
            "active_alerts": len(monitor.alerts),
            "blocked_ips": get_store().count_blocked_ips(),
            "average_trust_score": trust_stats["average_trust_score"],
            "risk_distribution": trust_stats["risk_distribution"],
        },
        "system_performance": monitor.get_metrics_summary(),
        "recent_events": [
            {
                "time": datetime.fromtimestamp(e.timestamp).strftime("%H:%M:%S"),
                "type": e.event_type,
                "severity": e.severity,
                "description": e.description,
            }
            for e in list(monitor.security_events)[-10:]
        ],
        "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
    }
