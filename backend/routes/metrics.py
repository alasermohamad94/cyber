import socket
import time

import psutil
from fastapi import APIRouter, Depends

from backend.services.monitor import format_bytes, format_duration, monitor
from security.config import demo_mode_enabled
from security.fastapi_auth import require_permission_dep
from storage.persistence import get_store
from trust_system.trust_manager import get_trust_statistics
from response.engine import get_response_summary
from backend.metrics_contract import METRIC_CONTRACT, data_quality_payload

router = APIRouter(tags=["metrics"])


@router.get("/api/demo/disclaimer")
async def demo_disclaimer():
    return {
        "demo_mode": demo_mode_enabled(),
        "production_path": "/api/system-metrics",
        "message": "Demo endpoints return synthetic data only when CDS_DEMO_MODE=true",
    }


@router.get("/api/metrics-contract")
async def metrics_contract(_role: str = Depends(require_permission_dep("metrics:read"))):
    return {
        "contract": METRIC_CONTRACT,
        "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
    }


@router.get("/api/system-metrics")
async def get_system_metrics_api(_role: str = Depends(require_permission_dep("metrics:read"))):
    metrics = monitor.get_system_metrics()
    return {
        "cpu_percent": metrics.cpu_percent,
        "memory_percent": metrics.memory_percent,
        "disk_usage": metrics.disk_usage,
        "network_io": metrics.network_io,
        "active_connections": metrics.active_connections,
        "system_load": metrics.system_load,
        "uptime": metrics.uptime,
        "timestamp": metrics.timestamp,
        "uptime_formatted": format_duration(metrics.uptime),
        "network_sent_formatted": format_bytes(metrics.network_io["bytes_sent"]),
        "network_recv_formatted": format_bytes(metrics.network_io["bytes_recv"]),
        "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
    }


@router.get("/api/analytics-overview")
async def get_analytics_overview(_role: str = Depends(require_permission_dep("metrics:read"))):
    metrics = monitor.get_system_metrics()
    summary = monitor.get_metrics_summary()
    history = monitor.get_metrics_history_series()
    trust_stats = get_trust_statistics()
    resp_summary = get_response_summary()
    day_start = time.time() - 86400
    events_by_severity = {
        "low": get_store().count_events_since(day_start, "low"),
        "medium": get_store().count_events_since(day_start, "medium"),
        "high": get_store().count_events_since(day_start, "high"),
        "critical": get_store().count_events_since(day_start, "critical"),
    }
    health = max(0.0, min(100.0, 100 - metrics.cpu_percent * 0.4 - max(0, metrics.memory_percent - 50) * 0.6))
    efficiency = max(0.0, min(100.0, 100 - (metrics.cpu_percent + metrics.memory_percent) / 2))
    return {
        "health_score": round(health, 1),
        "efficiency": round(efficiency, 1),
        "avg_cpu": summary.get("avg_cpu", metrics.cpu_percent),
        "avg_memory": summary.get("avg_memory", metrics.memory_percent),
        "active_connections": metrics.active_connections,
        "trust_statistics": trust_stats,
        "events_by_severity": events_by_severity,
        "response_summary": resp_summary,
        "performance_history": history,
        "resource_distribution": {
            "cpu": metrics.cpu_percent,
            "memory": metrics.memory_percent,
            "disk": metrics.disk_usage,
            "network": min(100.0, metrics.active_connections / 5.0),
        },
        "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
    }


@router.get("/api/processes")
async def get_processes(_role: str = Depends(require_permission_dep("metrics:read"))):
    processes = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            processes.append(
                {
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "cpu_percent": proc.info["cpu_percent"] or 0,
                    "memory_percent": proc.info["memory_percent"] or 0,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    processes.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return {"processes": processes[:20]}


@router.get("/api/network-interfaces")
async def get_network_interfaces(_role: str = Depends(require_permission_dep("metrics:read"))):
    interfaces = []
    net_if_addrs = psutil.net_if_addrs()
    net_if_stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    for interface, addrs in net_if_addrs.items():
        stats = net_if_stats.get(interface)
        if not stats:
            continue
        counter = counters.get(interface)
        interface_info = {
            "name": interface,
            "is_up": stats.isup,
            "speed": stats.speed,
            "mtu": stats.mtu,
            "bytes_sent": counter.bytes_sent if counter else 0,
            "bytes_recv": counter.bytes_recv if counter else 0,
            "addresses": [],
        }
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interface_info["addresses"].append(
                    {"type": "IPv4", "address": addr.address, "netmask": addr.netmask}
                )
        interfaces.append(interface_info)
    return {"interfaces": interfaces}
