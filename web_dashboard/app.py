"""
Cyber Defense System - Web Dashboard
==================================

Professional web-based server monitoring and security management interface.
Real-time monitoring with modern responsive design.
"""

import sys
import os
import json
import time
import threading
import psutil
import socket
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import system modules
from trust_system.trust_manager import get_trust_statistics, get_all_trust_records, update_trust_score
from response.engine import get_active_responses, get_response_history, execute_response, cancel_response
from main import CyberDefenseSystem

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber-defense-system-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

@dataclass
class ServerMetrics:
    """Server performance and resource metrics."""
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
    """Security event with full details."""
    event_id: str
    timestamp: float
    event_type: str
    severity: str
    source_ip: str
    target_entity: str
    description: str
    action_taken: str
    status: str

class WebServerMonitor:
    """Real-time server monitoring system for web interface."""
    
    def __init__(self):
        self.metrics_history = deque(maxlen=100)
        self.security_events = deque(maxlen=1000)
        self.alerts = deque(maxlen=100)
        self.blocked_ips = {}
        self.start_time = time.time()
        self.monitoring = True
        self.cds = CyberDefenseSystem()
        
    def get_system_metrics(self) -> ServerMetrics:
        """Collect current system metrics."""
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory metrics
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_usage = disk.percent
        
        # Network metrics
        network = psutil.net_io_counters()
        network_io = {
            'bytes_sent': network.bytes_sent,
            'bytes_recv': network.bytes_recv,
            'packets_sent': network.packets_sent,
            'packets_recv': network.packets_recv
        }
        
        # Network connections
        try:
            connections = len(psutil.net_connections())
        except:
            connections = 0
        
        # System load
        try:
            load_avg = list(psutil.getloadavg())
        except:
            load_avg = [0.0, 0.0, 0.0]
        
        # Uptime
        uptime = time.time() - self.start_time
        
        metrics = ServerMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_usage=disk_usage,
            network_io=network_io,
            active_connections=connections,
            system_load=load_avg,
            uptime=uptime,
            timestamp=time.time()
        )
        
        self.metrics_history.append(metrics)
        return metrics
    
    def add_security_event(self, event_type: str, severity: str, source_ip: str, 
                          target_entity: str, description: str, action_taken: str):
        """Add a new security event."""
        event = SecurityEvent(
            event_id=f"evt_{int(time.time())}_{len(self.security_events)}",
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            target_entity=target_entity,
            description=description,
            action_taken=action_taken,
            status="active"
        )
        self.security_events.append(event)
        
        # Add alert for high severity events
        if severity in ['high', 'critical']:
            self.alerts.append({
                'timestamp': time.time(),
                'message': f"{severity.upper()}: {description}",
                'event_id': event.event_id
            })
    
    def get_metrics_summary(self) -> dict:
        """Get summary of recent metrics."""
        if not self.metrics_history:
            return {}
        
        recent_metrics = list(self.metrics_history)[-10:]
        
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        
        return {
            'avg_cpu': avg_cpu,
            'avg_memory': avg_memory,
            'current_connections': recent_metrics[-1].active_connections,
            'uptime': recent_metrics[-1].uptime,
            'total_events': len(self.security_events),
            'active_alerts': len(self.alerts)
        }

    def get_metrics_history(self, limit: int = 30) -> list:
        """Return recent metrics as serializable trend samples."""
        return [
            {
                'timestamp': metrics.timestamp,
                'time_formatted': datetime.fromtimestamp(metrics.timestamp).strftime('%H:%M:%S'),
                'cpu_percent': metrics.cpu_percent,
                'memory_percent': metrics.memory_percent,
                'disk_usage': metrics.disk_usage,
                'active_connections': metrics.active_connections,
                'network_bytes_sent': metrics.network_io.get('bytes_sent', 0),
                'network_bytes_recv': metrics.network_io.get('bytes_recv', 0)
            }
            for metrics in list(self.metrics_history)[-limit:]
        ]
    
    def analyze_entity(self, entity_id: str, entity_data: dict) -> dict:
        """Analyze entity using cyber defense system."""
        try:
            result = self.cds.analyze_entity(entity_id, entity_data)
            
            # Add security event
            self.add_security_event(
                event_type="entity_analysis",
                severity=result['decision']['severity'],
                source_ip=entity_data.get('source_ip', 'unknown'),
                target_entity=entity_id,
                description=f"Entity analyzed with behavior score {result['behavior_profile']['behavior_score']:.1f}",
                action_taken=result['decision']['action']
            )
            
            return result
        except Exception as e:
            return {
                'error': str(e),
                'entity_id': entity_id,
                'timestamp': time.time()
            }

    def block_ip_address(self, ip_address: str, reason: str = 'manual_block') -> dict:
        """Record a blocked IP address and emit a real security event."""
        blocked_at = time.time()
        self.blocked_ips[ip_address] = {
            'ip_address': ip_address,
            'reason': reason,
            'blocked_at': blocked_at,
            'blocked_at_formatted': datetime.fromtimestamp(blocked_at).strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'active'
        }
        self.add_security_event(
            event_type="ip_blocked",
            severity="medium",
            source_ip=ip_address,
            target_entity="firewall",
            description=f"IP address {ip_address} blocked by administrator",
            action_taken="blocked"
        )
        return self.blocked_ips[ip_address]

    def unblock_ip_address(self, ip_address: str) -> bool:
        """Mark a blocked IP address as unblocked."""
        if ip_address not in self.blocked_ips:
            return False
        self.blocked_ips[ip_address]['status'] = 'unblocked'
        self.add_security_event(
            event_type="ip_unblocked",
            severity="low",
            source_ip=ip_address,
            target_entity="firewall",
            description=f"IP address {ip_address} unblocked by administrator",
            action_taken="unblocked"
        )
        return True

    def get_threat_summary(self) -> dict:
        """Build threat management data from actual security records."""
        events = list(self.security_events)
        active_threats = [
            event for event in events
            if event.status == 'active' and event.severity in {'high', 'critical'}
        ]
        response_history = get_response_history()
        resolved_today = 0
        today = datetime.now().date()
        for response in response_history:
            completion_time = response.get('completion_time')
            if completion_time and datetime.fromtimestamp(completion_time).date() == today:
                resolved_today += 1

        return {
            'active_threats': [
                {
                    'event_id': event.event_id,
                    'timestamp': event.timestamp,
                    'time_formatted': datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S'),
                    'event_type': event.event_type,
                    'severity': event.severity,
                    'source_ip': event.source_ip,
                    'target_entity': event.target_entity,
                    'description': event.description,
                    'action_taken': event.action_taken,
                    'status': event.status
                }
                for event in active_threats[-20:]
            ],
            'blocked_ips': [
                item for item in self.blocked_ips.values()
                if item.get('status') == 'active'
            ],
            'isolated_systems': [
                response for response in response_history
                if response.get('action_type') == 'isolate'
                and response.get('status') in {'pending', 'executing', 'completed'}
            ],
            'resolved_today': resolved_today,
            'recent_activity': [
                {
                    'timestamp': event.timestamp,
                    'time_formatted': datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S'),
                    'description': event.description,
                    'event_type': event.event_type,
                    'severity': event.severity
                }
                for event in events[-10:]
            ]
        }

# Global monitor instance
monitor = WebServerMonitor()

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def format_duration(seconds: float) -> str:
    """Format duration to human readable format."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"

# Routes
@app.route('/web_dashboard')
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')

@app.route('/analytics')
def analytics():
    """Analytics page."""
    return render_template('analytics.html')

@app.route('/threat-management')
def threat_management():
    """Threat management page."""
    return render_template('threat_management.html')

@app.route('/settings')
def settings():
    """Settings page."""
    return render_template('settings.html')

@app.route('/api/system-metrics')
def get_system_metrics():
    """API endpoint for system metrics."""
    metrics = monitor.get_system_metrics()
    return jsonify({
        'cpu_percent': metrics.cpu_percent,
        'memory_percent': metrics.memory_percent,
        'disk_usage': metrics.disk_usage,
        'network_io': metrics.network_io,
        'active_connections': metrics.active_connections,
        'system_load': metrics.system_load,
        'uptime': metrics.uptime,
        'timestamp': metrics.timestamp,
        'uptime_formatted': format_duration(metrics.uptime),
        'network_sent_formatted': format_bytes(metrics.network_io['bytes_sent']),
        'network_recv_formatted': format_bytes(metrics.network_io['bytes_recv'])
    })

@app.route('/api/dashboard-state')
def get_dashboard_state():
    """Single API endpoint for initial dashboard state."""
    start = time.time()
    metrics = monitor.get_system_metrics()
    security = build_security_overview()
    payload = {
        'system_metrics': {
            'cpu_percent': metrics.cpu_percent,
            'memory_percent': metrics.memory_percent,
            'disk_usage': metrics.disk_usage,
            'network_io': metrics.network_io,
            'active_connections': metrics.active_connections,
            'system_load': metrics.system_load,
            'uptime': metrics.uptime,
            'timestamp': metrics.timestamp,
            'uptime_formatted': format_duration(metrics.uptime),
            'network_sent_formatted': format_bytes(metrics.network_io['bytes_sent']),
            'network_recv_formatted': format_bytes(metrics.network_io['bytes_recv'])
        },
        'security_overview': security,
        'metrics_history': monitor.get_metrics_history(),
        'api_latency_ms': round((time.time() - start) * 1000, 2)
    }
    return jsonify(payload)

def build_security_overview() -> dict:
    """Collect security overview data from project services."""
    stats = get_trust_statistics()
    active_responses = get_active_responses()
    return {
        'trust_statistics': stats,
        'active_responses': active_responses,
        'total_events': len(monitor.security_events),
        'active_alerts': len(monitor.alerts),
        'recent_events': [
            {
                'event_id': event.event_id,
                'timestamp': event.timestamp,
                'event_type': event.event_type,
                'severity': event.severity,
                'source_ip': event.source_ip,
                'target_entity': event.target_entity,
                'description': event.description,
                'action_taken': event.action_taken,
                'time_formatted': datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S')
            }
            for event in list(monitor.security_events)[-10:]
        ]
    }

@app.route('/api/security-overview')
def get_security_overview():
    """API endpoint for security overview."""
    try:
        return jsonify(build_security_overview())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics-data')
def get_analytics_data():
    """API endpoint for analytics charts and metrics."""
    start = time.time()
    metrics = monitor.get_system_metrics()
    security = build_security_overview()
    risk_distribution = security['trust_statistics'].get('risk_distribution', {})
    events = list(monitor.security_events)
    severity_counts = {
        severity: sum(1 for event in events if event.severity == severity)
        for severity in ['low', 'medium', 'high', 'critical']
    }
    total_entities = security['trust_statistics'].get('total_entities', 0)
    high_risk_entities = risk_distribution.get('high', 0) + risk_distribution.get('critical', 0)
    detection_coverage = None
    if total_entities:
        detection_coverage = max(0, min(100, ((total_entities - high_risk_entities) / total_entities) * 100))

    return jsonify({
        'summary': {
            'system_health': max(0, min(100, 100 - max(metrics.cpu_percent, metrics.memory_percent, metrics.disk_usage))),
            'api_latency_ms': round((time.time() - start) * 1000, 2),
            'detection_coverage': detection_coverage,
            'resource_efficiency': max(0, min(100, 100 - ((metrics.cpu_percent + metrics.memory_percent + metrics.disk_usage) / 3)))
        },
        'current_metrics': {
            'cpu_percent': metrics.cpu_percent,
            'memory_percent': metrics.memory_percent,
            'disk_usage': metrics.disk_usage,
            'active_connections': metrics.active_connections,
            'network_io': metrics.network_io
        },
        'metrics_history': monitor.get_metrics_history(),
        'security_events_by_severity': severity_counts,
        'risk_distribution': risk_distribution,
        'threat_surface': {
            'network': min(100, metrics.active_connections),
            'system': max(metrics.cpu_percent, metrics.memory_percent, metrics.disk_usage),
            'application': risk_distribution.get('medium', 0) + risk_distribution.get('high', 0),
            'data': risk_distribution.get('critical', 0),
            'user': total_entities
        }
    })

@app.route('/api/analyze-entity', methods=['POST'])
def analyze_entity():
    """API endpoint for entity analysis."""
    try:
        data = request.get_json()
        entity_id = data.get('entity_id')
        entity_data = data.get('entity_data', {})
        
        if not entity_id:
            return jsonify({'error': 'Entity ID is required'}), 400
        
        result = monitor.analyze_entity(entity_id, entity_data)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    """API endpoint for IP blocking."""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        reason = data.get('reason', 'manual_block')
        
        if not ip_address:
            return jsonify({'error': 'IP address is required'}), 400
        
        # Basic IP validation
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, ip_address):
            return jsonify({'error': 'Invalid IP address format'}), 400

        blocked_ip = monitor.block_ip_address(ip_address, reason)
        return jsonify({
            'success': True,
            'message': f'IP {ip_address} blocked successfully',
            'blocked_ip': blocked_ip
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock-ip', methods=['POST'])
def unblock_ip():
    """API endpoint for IP unblocking."""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        if not ip_address:
            return jsonify({'error': 'IP address is required'}), 400
        if not monitor.unblock_ip_address(ip_address):
            return jsonify({'error': 'IP address is not blocked'}), 404
        return jsonify({'success': True, 'message': f'IP {ip_address} unblocked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats')
def get_threats():
    """API endpoint for threat management data."""
    try:
        return jsonify(monitor.get_threat_summary())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/security-report')
def get_security_report():
    """API endpoint for security report."""
    try:
        report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Get statistics
        trust_stats = get_trust_statistics()
        active_responses = get_active_responses()
        trust_records = get_all_trust_records()
        
        # Generate report
        report = {
            'generated_at': report_time,
            'executive_summary': {
                'total_entities': len(trust_records),
                'active_responses': len(active_responses),
                'total_events': len(monitor.security_events),
                'active_alerts': len(monitor.alerts),
                'average_trust_score': trust_stats['average_trust_score'],
                'risk_distribution': trust_stats['risk_distribution']
            },
            'system_performance': monitor.get_metrics_summary(),
            'recent_events': [
                {
                    'time': datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S'),
                    'type': event.event_type,
                    'severity': event.severity,
                    'description': event.description
                }
                for event in list(monitor.security_events)[-10:]
            ],
            'recommendations': [
                'Continue regular monitoring and updates',
                'Implement automated threat response',
                'Regular security audits',
                'Employee security training'
            ]
        }
        
        return jsonify(report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/processes')
def get_processes():
    """API endpoint for process information."""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'cpu_percent': proc.info['cpu_percent'] or 0,
                    'memory_percent': proc.info['memory_percent'] or 0
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        return jsonify({'processes': processes[:20]})  # Return top 20
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network-interfaces')
def get_network_interfaces():
    """API endpoint for network interface information."""
    try:
        interfaces = []
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        net_if_counters = psutil.net_io_counters(pernic=True)
        
        for interface, addrs in net_if_addrs.items():
            stats = net_if_stats.get(interface)
            if stats:
                interface_info = {
                    'name': interface,
                    'is_up': stats.isup,
                    'speed': stats.speed,
                    'mtu': stats.mtu,
                    'addresses': []
                }
                counters = net_if_counters.get(interface)
                if counters:
                    interface_info['traffic'] = {
                        'bytes_sent': counters.bytes_sent,
                        'bytes_recv': counters.bytes_recv,
                        'packets_sent': counters.packets_sent,
                        'packets_recv': counters.packets_recv,
                        'bytes_sent_formatted': format_bytes(counters.bytes_sent),
                        'bytes_recv_formatted': format_bytes(counters.bytes_recv)
                    }
                else:
                    interface_info['traffic'] = None
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interface_info['addresses'].append({
                            'type': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                    elif addr.family == socket.AF_INET6:
                        interface_info['addresses'].append({
                            'type': 'IPv6',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                
                interfaces.append(interface_info)
        
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# WebSocket events for real-time updates
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    print(f"Client connected: {request.sid}")
    emit('status', {'message': 'Connected to Cyber Defense System'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    print(f"Client disconnected: {request.sid}")

def broadcast_metrics():
    """Broadcast system metrics to connected clients."""
    while True:
        try:
            metrics = monitor.get_system_metrics()
            socketio.emit('metrics_update', {
                'cpu_percent': metrics.cpu_percent,
                'memory_percent': metrics.memory_percent,
                'disk_usage': metrics.disk_usage,
                'active_connections': metrics.active_connections,
                'uptime_formatted': format_duration(metrics.uptime),
                'timestamp': metrics.timestamp
            })
            socketio.sleep(2)  # Update every 2 seconds
        except Exception as e:
            print(f"Error broadcasting metrics: {e}")
            socketio.sleep(5)

def broadcast_security_updates():
    """Broadcast security updates to connected clients."""
    last_alert_count = 0
    while True:
        try:
            current_alert_count = len(monitor.alerts)
            if current_alert_count > last_alert_count:
                # New alert detected
                latest_alert = monitor.alerts[-1]
                socketio.emit('security_alert', {
                    'message': latest_alert['message'],
                    'timestamp': latest_alert['timestamp'],
                    'event_id': latest_alert['event_id']
                })
                last_alert_count = current_alert_count
            
            socketio.sleep(5)  # Check every 5 seconds
        except Exception as e:
            print(f"Error broadcasting security updates: {e}")
            socketio.sleep(10)

# Start background threads for real-time updates
def start_background_threads():
    """Start background threads for real-time updates."""
    metrics_thread = threading.Thread(target=broadcast_metrics, daemon=True)
    metrics_thread.start()
    
    security_thread = threading.Thread(target=broadcast_security_updates, daemon=True)
    security_thread.start()

if __name__ == '__main__':
    start_background_threads()
    socketio.run(app, host='0.0.0.0', port=8080, debug=False)
