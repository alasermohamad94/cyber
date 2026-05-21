"""
Unified metric contract: name, source, freshness, precision.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


METRIC_CONTRACT: List[Dict[str, str]] = [
    {
        "name": "cpu_percent",
        "source": "psutil",
        "endpoint": "/api/system-metrics",
        "precision": "0.1%",
    },
    {
        "name": "memory_percent",
        "source": "psutil",
        "endpoint": "/api/system-metrics",
        "precision": "0.1%",
    },
    {
        "name": "disk_usage",
        "source": "psutil",
        "endpoint": "/api/system-metrics",
        "precision": "0.1%",
    },
    {
        "name": "active_connections",
        "source": "psutil",
        "endpoint": "/api/system-metrics",
        "precision": "integer",
    },
    {
        "name": "trust_statistics",
        "source": "trust_system",
        "endpoint": "/api/security-overview",
        "precision": "aggregated",
    },
    {
        "name": "active_responses",
        "source": "response_engine",
        "endpoint": "/api/threat-overview",
        "precision": "integer",
    },
    {
        "name": "blocked_ips",
        "source": "security_store",
        "endpoint": "/api/blocked-ips",
        "precision": "integer",
    },
    {
        "name": "security_events",
        "source": "security_store",
        "endpoint": "/api/security-overview",
        "precision": "event_log",
    },
]


def data_quality_payload(
    last_metrics_ts: float,
    store_ok: bool = True,
    error: str = "",
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).timestamp()
    age = now - last_metrics_ts if last_metrics_ts else None
    return {
        "data_mode": "production",
        "source_status": "ok" if store_ok and not error else "degraded",
        "freshness_seconds": round(age, 2) if age is not None else None,
        "error_state": error or None,
        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
