"""
Advanced query engine for security events with compound filters.
"""

from typing import Any, Dict, List, Optional

from storage.persistence import get_store


def query_events(
    filters: Optional[Dict[str, Any]] = None,
    logic: str = "and",
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    """
    Query security events with compound filters.

    Supported filter keys: severity, event_type, source_ip, target_entity,
    since, until, status, search (text in description).
    """
    filters = filters or {}
    store = get_store()
    events = store.list_security_events(limit=2000)

    def matches(event: Dict[str, Any]) -> bool:
        checks = []
        if "severity" in filters:
            val = filters["severity"]
            if isinstance(val, list):
                checks.append(event.get("severity") in val)
            else:
                checks.append(event.get("severity") == val)
        if "event_type" in filters:
            checks.append(event.get("event_type") == filters["event_type"])
        if "source_ip" in filters:
            checks.append(event.get("source_ip") == filters["source_ip"])
        if "target_entity" in filters:
            checks.append(event.get("target_entity") == filters["target_entity"])
        if "status" in filters:
            checks.append(event.get("status") == filters["status"])
        if "since" in filters:
            checks.append(event.get("timestamp", 0) >= float(filters["since"]))
        if "until" in filters:
            checks.append(event.get("timestamp", 0) <= float(filters["until"]))
        if "search" in filters:
            term = str(filters["search"]).lower()
            desc = (event.get("description") or "").lower()
            checks.append(term in desc)
        if not checks:
            return True
        return all(checks) if logic == "and" else any(checks)

    filtered = [e for e in events if matches(e)]
    filtered.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    total = len(filtered)
    page = filtered[offset : offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "events": page}


def replay_events(
    entity_id: Optional[str] = None,
    since: Optional[float] = None,
    until: Optional[float] = None,
    source_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Build chronological replay payload for forensic viewer."""
    filters: Dict[str, Any] = {}
    if entity_id:
        filters["target_entity"] = entity_id
    if source_ip:
        filters["source_ip"] = source_ip
    if since:
        filters["since"] = since
    if until:
        filters["until"] = until

    result = query_events(filters=filters, limit=500)
    events = sorted(result["events"], key=lambda e: e.get("timestamp", 0))

    trust_snapshots = []
    if entity_id:
        record = get_store().get_trust_record(entity_id)
        if record:
            trust_snapshots.append(
                {
                    "timestamp": record.get("last_updated"),
                    "trust_score": record.get("trust_score"),
                    "risk_score": record.get("risk_score"),
                    "risk_level": record.get("risk_level"),
                }
            )

    return {
        "entity_id": entity_id,
        "source_ip": source_ip,
        "event_count": len(events),
        "events": events,
        "trust_snapshots": trust_snapshots,
        "time_range": {
            "start": events[0]["timestamp"] if events else None,
            "end": events[-1]["timestamp"] if events else None,
        },
    }


__all__ = ["query_events", "replay_events"]
