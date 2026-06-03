"""
Cyber Defense System - Web Dashboard
"""

import os
import re
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

import psutil
import socket
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_socketio import SocketIO, emit

WEB_DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(WEB_DASHBOARD_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if WEB_DASHBOARD_DIR not in sys.path:
    sys.path.insert(0, WEB_DASHBOARD_DIR)

from main import CyberDefenseSystem
from response.engine import (
    execute_response,
    get_active_responses,
    get_recent_responses,
    get_response_history,
    get_response_summary,
)
from security.auth import (
    api_login_required,
    get_current_role,
    is_authenticated,
    login_required,
    login_user,
    logout_user,
    require_permission,
    verify_credentials,
)
from security.config import (
    demo_mode_enabled,
    env_loaded_path,
    get_bind_host,
    get_bind_port,
    get_cors_origins,
    get_login_display_info,
    get_secret_key,
)
from security.roles import Role, permissions_for_role, role_has_permission
from workers.background_queue import get_background_queue
from security.firewall import apply_firewall_block, remove_firewall_block, validate_ip
from storage.persistence import get_store
from trust_system.trust_manager import get_all_trust_records, get_trust_statistics
from metrics_contract import METRIC_CONTRACT, data_quality_payload

app = Flask(__name__)
app.config["SECRET_KEY"] = get_secret_key()
socketio = SocketIO(app, cors_allowed_origins=get_cors_origins(), async_mode="threading")

_store = get_store()


def _cds_has_perm(permission: str) -> bool:
    if not is_authenticated():
        return False
    return role_has_permission(get_current_role(), permission)


@app.context_processor
def inject_rbac():
    role = get_current_role() if is_authenticated() else ""
    return {
        "cds_role": role,
        "cds_permissions": permissions_for_role(role) if role else [],
        "cds_has_perm": _cds_has_perm,
    }


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
    """Non-blocking CPU sampling for API and broadcast paths."""

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
        for event in _store.list_security_events(limit=200):
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
    ):
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
            _store.save_security_event(
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
            if severity in ("high", "critical"):
                self.alerts.append(
                    {
                        "timestamp": time.time(),
                        "message": f"{severity.upper()}: {description}",
                        "event_id": event.event_id,
                    }
                )

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


monitor = WebServerMonitor()


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


def _serialize_events(limit: int = 10):
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


@app.route("/")
def root():
    """Root always sends users to dashboard or login (never an empty page)."""
    if is_authenticated():
        return redirect(url_for("index"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        role = verify_credentials(username, password)
        if role:
            login_user(username, role)
            return redirect(url_for("index"))
        return render_template(
            "login.html",
            error="بيانات الدخول غير صحيحة. راجع جدول كلمات المرور أدناه (قد تكون مُعرّفة في .env أو CDS_*_PASSWORD).",
            accounts=get_login_display_info(),
            env_file=env_loaded_path(),
        )
    if is_authenticated():
        return redirect(url_for("index"))
    return render_template(
        "login.html",
        error=None,
        accounts=get_login_display_info(),
        env_file=env_loaded_path(),
    )


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/web_dashboard")
@login_required
def index():
    return render_template("dashboard.html")


@app.route("/dashboard")
@login_required
def dashboard_alias():
    """Legacy alias → canonical dashboard URL."""
    return redirect(url_for("index"))


@app.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html")


@app.route("/threat-management")
@login_required
def threat_management():
    return render_template("threat_management.html")


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@app.route("/api/session-info")
@api_login_required
def session_info():
    role = get_current_role()
    perms = permissions_for_role(role)
    return jsonify({
        "username": session.get("username"),
        "role": role,
        "permissions": perms,
        "demo_mode": demo_mode_enabled(),
        "demo_mode_available": demo_mode_enabled(),
    })


@app.route("/api/demo/disclaimer")
def demo_disclaimer():
    """Public note: demo data is isolated from production metrics."""
    return jsonify({
        "demo_mode": demo_mode_enabled(),
        "production_path": "/api/system-metrics",
        "message": "Demo endpoints return synthetic data only when CDS_DEMO_MODE=true",
    })


@app.route("/api/metrics-contract")
@require_permission("metrics:read")
def metrics_contract():
    return jsonify(
        {
            "contract": METRIC_CONTRACT,
            "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
        }
    )


@app.route("/api/system-metrics")
@require_permission("metrics:read")
def get_system_metrics_api():
    metrics = monitor.get_system_metrics()
    return jsonify(
        {
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
    )


@app.route("/api/security-overview")
@require_permission("security:read")
def get_security_overview():
    try:
        return jsonify(
            {
                "trust_statistics": get_trust_statistics(),
                "active_responses": get_active_responses(),
                "recent_responses": get_recent_responses(10),
                "response_summary": get_response_summary(),
                "total_events": len(monitor.security_events),
                "active_alerts": len(monitor.alerts),
                "recent_events": _serialize_events(10),
                "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
            }
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/analytics-overview")
@require_permission("metrics:read")
def get_analytics_overview():
    """Unified analytics KPIs from real backends only."""
    metrics = monitor.get_system_metrics()
    summary = monitor.get_metrics_summary()
    history = monitor.get_metrics_history_series()
    trust_stats = get_trust_statistics()
    resp_summary = get_response_summary()
    day_start = time.time() - 86400
    events_by_severity = {
        "low": _store.count_events_since(day_start, "low"),
        "medium": _store.count_events_since(day_start, "medium"),
        "high": _store.count_events_since(day_start, "high"),
        "critical": _store.count_events_since(day_start, "critical"),
    }
    health = max(0.0, min(100.0, 100 - metrics.cpu_percent * 0.4 - max(0, metrics.memory_percent - 50) * 0.6))
    efficiency = max(0.0, min(100.0, 100 - (metrics.cpu_percent + metrics.memory_percent) / 2))
    return jsonify(
        {
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
    )


@app.route("/api/threat-overview")
@require_permission("security:read")
def get_threat_overview():
    """Threat page metrics from store + engines."""
    day_start = time.time() - 86400
    high_events = [
        e for e in _store.list_security_events(50)
        if e["severity"] in ("high", "critical")
    ]
    blocked = _store.list_blocked_ips(active_only=True)
    resp_summary = get_response_summary()
    risk_dist = get_trust_statistics().get("risk_distribution", {})
    return jsonify(
        {
            "active_threats": len(high_events),
            "blocked_ips_count": len(blocked),
            "blocked_ips": blocked,
            "isolated_systems": resp_summary.get("isolated_systems", 0),
            "resolved_today": resp_summary.get("resolved_today", 0),
            "active_responses": get_active_responses(),
            "recent_responses": get_recent_responses(15),
            "high_risk_events": high_events,
            "risk_distribution": risk_dist,
            "timeline": _serialize_events(15),
            "data_quality": data_quality_payload(monitor.cpu_sampler.last_sample_time()),
        }
    )


@app.route("/api/blocked-ips")
@require_permission("security:read")
def list_blocked_ips():
    rows = _store.list_blocked_ips(active_only=True)
    for row in rows:
        row["blocked_at_formatted"] = datetime.fromtimestamp(row["blocked_at"]).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    return jsonify({"blocked_ips": rows, "count": len(rows)})


@app.route("/api/analyze-entity", methods=["POST"])
@require_permission("entity:analyze")
def analyze_entity():
    try:
        data = request.get_json() or {}
        entity_id = data.get("entity_id")
        entity_data = data.get("entity_data", {})
        if not entity_id:
            return jsonify({"error": "Entity ID is required"}), 400
        result = monitor.analyze_entity(entity_id, entity_data)
        if "decision" in result:
            execute_response(entity_id, result["decision"])
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/block-ip", methods=["POST"])
@require_permission("ip:block")
def block_ip():
    try:
        data = request.get_json() or {}
        ip_address = data.get("ip_address")
        reason = data.get("reason", "manual_block")
        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400
        if not validate_ip(ip_address):
            return jsonify({"error": "Invalid IP address format"}), 400

        applied, fw_message = apply_firewall_block(ip_address)
        _store.save_blocked_ip(ip_address, reason, applied)
        monitor.add_security_event(
            event_type="ip_blocked",
            severity="medium",
            source_ip=ip_address,
            target_entity="firewall",
            description=f"IP {ip_address} blocked ({reason})",
            action_taken="blocked" if applied else "policy_recorded",
        )
        return jsonify(
            {
                "success": True,
                "firewall_applied": applied,
                "message": fw_message,
                "ip_address": ip_address,
            }
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/unblock-ip", methods=["POST"])
@require_permission("ip:unblock")
def unblock_ip():
    try:
        data = request.get_json() or {}
        ip_address = data.get("ip_address")
        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400
        if not validate_ip(ip_address):
            return jsonify({"error": "Invalid IP address format"}), 400

        removed, fw_message = remove_firewall_block(ip_address)
        released = _store.unblock_ip(ip_address)
        if not released and not removed:
            return jsonify({"error": "IP not found in block list"}), 404

        monitor.add_security_event(
            event_type="ip_unblocked",
            severity="low",
            source_ip=ip_address,
            target_entity="firewall",
            description=f"IP {ip_address} unblocked",
            action_taken="unblocked",
        )
        return jsonify({"success": True, "message": fw_message})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/security-report")
@require_permission("report:generate")
def get_security_report():
    try:
        trust_stats = get_trust_statistics()
        trust_records = get_all_trust_records()
        return jsonify(
            {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "executive_summary": {
                    "total_entities": len(trust_records),
                    "active_responses": len(get_active_responses()),
                    "recent_responses": len(get_recent_responses(20)),
                    "total_events": len(monitor.security_events),
                    "active_alerts": len(monitor.alerts),
                    "blocked_ips": _store.count_blocked_ips(),
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
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/processes")
@require_permission("metrics:read")
def get_processes():
    try:
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
        return jsonify({"processes": processes[:20]})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/network-interfaces")
@require_permission("metrics:read")
def get_network_interfaces():
    try:
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
        return jsonify({"interfaces": interfaces})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@socketio.on("connect")
def handle_connect():
    if not is_authenticated():
        return False
    emit("status", {"message": "Connected to Cyber Defense System"})


@socketio.on("disconnect")
def handle_disconnect():
    pass


def broadcast_metrics():
    while True:
        try:
            metrics = monitor.get_system_metrics()
            socketio.emit(
                "metrics_update",
                {
                    "cpu_percent": metrics.cpu_percent,
                    "memory_percent": metrics.memory_percent,
                    "disk_usage": metrics.disk_usage,
                    "active_connections": metrics.active_connections,
                    "uptime_formatted": format_duration(metrics.uptime),
                    "timestamp": metrics.timestamp,
                },
            )
            socketio.sleep(2)
        except Exception as exc:
            print(f"Error broadcasting metrics: {exc}")
            socketio.sleep(5)


def broadcast_security_updates():
    last_alert_count = 0
    while True:
        try:
            current = len(monitor.alerts)
            if current > last_alert_count:
                latest = monitor.alerts[-1]
                socketio.emit(
                    "security_alert",
                    {
                        "message": latest["message"],
                        "timestamp": latest["timestamp"],
                        "event_id": latest["event_id"],
                    },
                )
                last_alert_count = current
            socketio.sleep(5)
        except Exception as exc:
            print(f"Error broadcasting security updates: {exc}")
            socketio.sleep(10)


def start_background_threads():
    get_background_queue()
    threading.Thread(target=broadcast_metrics, daemon=True).start()
    threading.Thread(target=broadcast_security_updates, daemon=True).start()


if __name__ == "__main__":
    start_background_threads()
    socketio.run(app, host=get_bind_host(), port=get_bind_port(), debug=False)
