"""
Security incident management and case management API.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from security.fastapi_auth import require_permission_dep
from storage.persistence import CASE_STATUSES, INCIDENT_STATUSES, get_store

router = APIRouter(tags=["incidents"])


class CreateIncidentBody(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"
    assigned_to: Optional[str] = None
    event_ids: List[str] = []


class UpdateIncidentBody(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class LinkEventBody(BaseModel):
    event_id: str


class CreateCaseBody(BaseModel):
    title: str
    description: str = ""
    incident_ids: List[str] = []


class UpdateCaseBody(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None


class LinkIncidentBody(BaseModel):
    incident_id: str


@router.get("/api/incidents")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    case_id: Optional[str] = None,
    limit: int = 100,
    _role: str = Depends(require_permission_dep("incidents:read")),
):
    rows = get_store().list_incidents(
        status=status, severity=severity, assigned_to=assigned_to, case_id=case_id, limit=limit
    )
    return {"incidents": rows, "count": len(rows), "statuses": list(INCIDENT_STATUSES)}


@router.post("/api/incidents")
async def create_incident(
    body: CreateIncidentBody,
    request: Request,
    role: str = Depends(require_permission_dep("incidents:write")),
):
    incident = get_store().create_incident(
        title=body.title,
        description=body.description,
        severity=body.severity,
        assigned_to=body.assigned_to,
        event_ids=body.event_ids,
    )
    get_store().append_audit_log(
        actor=request.session.get("username", role),
        action="incident_created",
        details={"incident_id": incident["incident_id"], "title": body.title, "severity": body.severity},
    )
    return incident


@router.get("/api/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    _role: str = Depends(require_permission_dep("incidents:read")),
):
    incident = get_store().get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident["events"] = get_store().list_incident_events(incident_id)
    return incident


@router.patch("/api/incidents/{incident_id}")
async def update_incident(
    incident_id: str,
    body: UpdateIncidentBody,
    request: Request,
    role: str = Depends(require_permission_dep("incidents:write")),
):
    if not get_store().get_incident(incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.status and body.status not in INCIDENT_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {INCIDENT_STATUSES}")
    try:
        incident = get_store().update_incident(incident_id, **body.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    get_store().append_audit_log(
        actor=request.session.get("username", role),
        action="incident_updated",
        details={"incident_id": incident_id, "changes": body.model_dump(exclude_unset=True)},
    )
    return incident


@router.post("/api/incidents/{incident_id}/events")
async def link_event_to_incident(
    incident_id: str,
    body: LinkEventBody,
    request: Request,
    role: str = Depends(require_permission_dep("incidents:write")),
):
    if not get_store().get_incident(incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
    get_store().link_event_to_incident(incident_id, body.event_id)
    get_store().append_audit_log(
        actor=request.session.get("username", role),
        action="incident_event_linked",
        details={"incident_id": incident_id, "event_id": body.event_id},
    )
    return get_store().get_incident(incident_id)


@router.get("/api/cases")
async def list_cases(
    status: Optional[str] = None,
    limit: int = 100,
    _role: str = Depends(require_permission_dep("cases:read")),
):
    rows = get_store().list_cases(status=status, limit=limit)
    return {"cases": rows, "count": len(rows), "statuses": list(CASE_STATUSES)}


@router.post("/api/cases")
async def create_case(
    body: CreateCaseBody,
    request: Request,
    role: str = Depends(require_permission_dep("cases:write")),
):
    case = get_store().create_case(title=body.title, description=body.description, incident_ids=body.incident_ids)
    get_store().append_audit_log(
        actor=request.session.get("username", role),
        action="case_created",
        details={"case_id": case["case_id"], "title": body.title, "incident_ids": body.incident_ids},
    )
    return case


@router.get("/api/cases/{case_id}")
async def get_case(
    case_id: str,
    _role: str = Depends(require_permission_dep("cases:read")),
):
    case = get_store().get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case["incidents"] = [get_store().get_incident(i) for i in case["incident_ids"]]
    return case


@router.patch("/api/cases/{case_id}")
async def update_case(
    case_id: str,
    body: UpdateCaseBody,
    request: Request,
    role: str = Depends(require_permission_dep("cases:write")),
):
    if not get_store().get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    if body.status and body.status not in CASE_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {CASE_STATUSES}")
    try:
        case = get_store().update_case(case_id, **body.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    get_store().append_audit_log(
        actor=request.session.get("username", role),
        action="case_updated",
        details={"case_id": case_id, "changes": body.model_dump(exclude_unset=True)},
    )
    return case


@router.post("/api/cases/{case_id}/incidents")
async def link_incident_to_case(
    case_id: str,
    body: LinkIncidentBody,
    request: Request,
    role: str = Depends(require_permission_dep("cases:write")),
):
    if not get_store().get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    if not get_store().get_incident(body.incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
    get_store().link_incident_to_case(case_id, body.incident_id)
    get_store().append_audit_log(
        actor=request.session.get("username", role),
        action="case_incident_linked",
        details={"case_id": case_id, "incident_id": body.incident_id},
    )
    return get_store().get_case(case_id)
