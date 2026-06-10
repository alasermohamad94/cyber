"""
Server monitoring and security event orchestration for the web API.
"""

import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime

import psutil

from main import CyberDefenseSystem
from storage.persistence import get_store


@dataclass
class ServerMetrics:
    cpu_percent: float
    memory_percent: float
    disk_usage: float
    network_io: dict
    active_connections: int
    system_load: list
    uptime: float
    timestamp: float


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: float
    event_type: str
    severity: str
    source_ip: str
    target_entity: str
    description: str
    action_taken: str
    status: str


class CpuSampler:
    def __init__(self):
        self._lock = threading.Lock()
        self._cpu_percent = 0.0
        self._last_sample = 0.0
        psutil.cpu_percent(interval=None)
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self._running:
            value = psutil.cpu_percent(interval=1.0)
            with self._lock:
                self._cpu_percent = value
                self._last_sample = time.time()

    def get(self) -> float:
        with self._lock:
            return self._cpu_percent

    def last_sample_time(self) -> float:
        with self._lock:
            return self._last_sample


class WebServerMonitor:
    def __init__(self):
        self._lock = threading.RLock()
        self.metrics_history = deque(maxlen=100)
        self.security_events = deque(maxlen=1000)
        self.alerts = deque(maxlen=100)
        self.start_time = time.time()
        self.cds = CyberDefenseSystem()
        self.cpu_sampler = CpuSampler()
        self._load_events()

    def _load_events(self):
        for event in get_store().list_security_events(limit=200):
            self.security_events.append(
                SecurityEvent(
                    event_id=event["event_id"],
                    timestamp=event["timestamp"],
                    event_type=event["event_type"],
                    severity=event["severity"],
                    source_ip=event.get("source_ip", ""),
                    target_entity=event.get("target_entity", ""),
                    description=event.get("description", ""),
                    action_taken=event.get("action_taken", ""),
                    status=event.get("status", "active"),
                )
            )

    def get_system_metrics(self) -> ServerMetrics:
        with self._lock:
            cpu_percent = self.cpu_sampler.get()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            network = psutil.net_io_counters()
            network_io = {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv,
            }
            try:
                connections = len(psutil.net_connections())
            except (psutil.Error, OSError):
                connections = 0
            try:
                load_avg = list(psutil.getloadavg())
            except (AttributeError, OSError):
                load_avg = [0.0, 0.0, 0.0]

            metrics = ServerMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                disk_usage=disk.percent,
                network_io=network_io,
                active_connections=connections,
                system_load=load_avg,
                uptime=time.time() - self.start_time,
                timestamp=time.time(),
            )
            self.metrics_history.append(metrics)
            return metrics

    def add_security_event(
        self,
        event_type: str,
        severity: str,
        source_ip: str,
        target_entity: str,
        description: str,
        action_taken: str,
    ) -> str:
        with self._lock:
            event = SecurityEvent(
                event_id=f"evt_{int(time.time())}_{len(self.security_events)}",
                timestamp=time.time(),
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                target_entity=target_entity,
                description=description,
                action_taken=action_taken,
                status="active",
            )
            self.security_events.append(event)
            get_store().save_security_event(
                {
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "source_ip": event.source_ip,
                    "target_entity": event.target_entity,
                    "description": event.description,
                    "action_taken": event.action_taken,
                    "status": event.status,
                }
            )
            try:
                from security.audit_chain import get_audit_chain

                get_audit_chain().append(
                    "security_event",
                    "system",
                    {
                        "event_id": event.event_id,
                        "event_type": event_type,
                        "severity": severity,
                        "description": description,
                    },
                )
            except Exception:
                pass
            if severity in ("high", "critical"):
                self.alerts.append(
                    {
                        "timestamp": time.time(),
                        "message": f"{severity.upper()}: {description}",
                        "event_id": event.event_id,
                    }
                )
            return event.event_id

    def get_metrics_summary(self) -> dict:
        with self._lock:
            if not self.metrics_history:
                return {}
            recent = list(self.metrics_history)[-10:]
            return {
                "avg_cpu": sum(m.cpu_percent for m in recent) / len(recent),
                "avg_memory": sum(m.memory_percent for m in recent) / len(recent),
                "current_connections": recent[-1].active_connections,
                "uptime": recent[-1].uptime,
                "total_events": len(self.security_events),
                "active_alerts": len(self.alerts),
            }

    def analyze_entity(self, entity_id: str, entity_data: dict) -> dict:
        try:
            result = self.cds.analyze_entity(entity_id, entity_data)
            self.add_security_event(
                event_type="entity_analysis",
                severity=result["decision"]["severity"],
                source_ip=entity_data.get("source_ip", "unknown"),
                target_entity=entity_id,
                description=(
                    f"Entity analyzed with behavior score "
                    f"{result['behavior_profile']['behavior_score']:.1f}"
                ),
                action_taken=result["decision"]["action"],
            )
            correlation = result.get("correlation", {})
            if correlation.get("correlated"):
                corr_event = self.add_security_event(
                    event_type=correlation.get("incident_type", "correlated_incident"),
                    severity=correlation.get("severity", result["decision"]["severity"]),
                    source_ip=correlation.get("source_ip", entity_data.get("source_ip", "")),
                    target_entity=entity_id,
                    description=correlation.get(
                        "reasoning",
                        "Correlated multi-stage incident detected automatically.",
                    ),
                    action_taken=result["decision"]["action"],
                )
                try:
                    from soc.incident_manager import get_incident_manager
                    from decision_engine.escalation import get_escalation_manager

                    event_ids = [corr_event] if corr_event else []
                    incident = get_incident_manager().create_from_correlation(
                        correlation, entity_id, event_ids=event_ids
                    )
                    if result["decision"].get("action") == "alert":
                        get_escalation_manager().register_alert(
                            entity_id, incident["incident_id"], "alert"
                        )
                    result["incident"] = incident
                except Exception:
                    pass
            return result
        except Exception as exc:
            return {"error": str(exc), "entity_id": entity_id, "timestamp": time.time()}

    def get_metrics_history_series(self, limit: int = 30) -> dict:
        with self._lock:
            items = list(self.metrics_history)[-limit:]
            return {
                "labels": [
                    datetime.fromtimestamp(m.timestamp).strftime("%H:%M:%S") for m in items
                ],
                "cpu": [m.cpu_percent for m in items],
                "memory": [m.memory_percent for m in items],
                "disk": [m.disk_usage for m in items],
            }


def format_bytes(bytes_value: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_duration(seconds: float) -> str:
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def serialize_events(monitor: WebServerMonitor, limit: int = 10):
    return [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "severity": e.severity,
            "source_ip": e.source_ip,
            "target_entity": e.target_entity,
            "description": e.description,
            "action_taken": e.action_taken,
            "time_formatted": datetime.fromtimestamp(e.timestamp).strftime("%H:%M:%S"),
        }
        for e in list(monitor.security_events)[-limit:]
    ]


monitor = WebServerMonitor()
