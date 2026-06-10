"""
Forensics API: immutable audit log verification, event replay, and the
advanced query engine over security events.
"""

from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security.fastapi_auth import require_permission_dep
from storage.persistence import QUERY_FIELDS, QUERY_OPERATORS, get_store

router = APIRouter(tags=["forensics"])


class QueryFilter(BaseModel):
    field: str
    op: str
    value: Any = None


class QueryBody(BaseModel):
    filters: List[QueryFilter] = []
    logic: str = "AND"
    limit: int = 100


@router.get("/api/audit-logs")
async def list_audit_logs(
    limit: int = 100,
    _role: str = Depends(require_permission_dep("audit:verify")),
):
    return {"logs": get_store().list_audit_logs(limit=limit)}


@router.get("/api/audit-logs/verify")
async def verify_audit_logs(
    _role: str = Depends(require_permission_dep("audit:verify")),
):
    return get_store().verify_audit_chain()


@router.get("/api/forensics/replay")
async def replay_events(
    target_entity: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
    limit: int = 500,
    _role: str = Depends(require_permission_dep("forensics:read")),
):
    events = get_store().replay_events(
        target_entity=target_entity, start_ts=start_ts, end_ts=end_ts, limit=limit
    )
    return {"events": events, "count": len(events)}


@router.post("/api/forensics/query")
async def query_events(
    body: QueryBody,
    _role: str = Depends(require_permission_dep("forensics:read")),
):
    for f in body.filters:
        if f.field not in QUERY_FIELDS:
            raise HTTPException(status_code=400, detail=f"Unknown field: {f.field}")
        if f.op not in QUERY_OPERATORS:
            raise HTTPException(status_code=400, detail=f"Unknown operator: {f.op}")
    events = get_store().query_events(
        filters=[f.model_dump() for f in body.filters], logic=body.logic, limit=body.limit
    )
    return {
        "events": events,
        "count": len(events),
        "available_fields": list(QUERY_FIELDS),
        "available_operators": list(QUERY_OPERATORS),
    }
