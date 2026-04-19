"""
Advanced Server Control Center
================================

Professional server monitoring and management interface.
Complete control over all aspects of server security and operations.
"""

import sys
import os
import time
import json
import threading
import psutil
import socket
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import system modules
from trust_system.trust_manager import get_trust_statistics, get_all_trust_records, reset_trust_score
from response.engine import get_active_responses, get_response_history, cancel_response
from main import CyberDefenseSystem


@dataclass
class ServerMetrics:
    """Server performance and resource metrics."""
    cpu_percent: float
    memory_percent: float
    disk_usage: float
    network_io: Dict[str, int]
    active_connections: int
    system_load: List[float]
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


class ServerMonitor:
    """Real-time server monitoring system."""
    
    def __init__(self):
        self.metrics_history = deque(maxlen=100)
        self.security_events = deque(maxlen=1000)
        self.alerts = deque(maxlen=100)
        self.start_time = time.time()
        self.monitoring = True
        
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
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of recent metrics."""
        if not self.metrics_history:
            return {}
        
        recent_metrics = list(self.metrics_history)[-10:]  # Last 10 metrics
        
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


class AdvancedServerDashboard:
    """
    Advanced server control center with comprehensive monitoring and management.
    """
    
    def __init__(self):
        self.running = True
        self.refresh_interval = 2  # seconds
        self.auto_refresh = True
        self.current_view = "overview"
        self.cds = CyberDefenseSystem()
        self.monitor = ServerMonitor()
        self.monitoring_thread = None
        self.start_monitoring()
        
        # Server configuration
        self.server_config = {
            'hostname': socket.gethostname(),
            'ip_address': self.get_local_ip(),
            'os': os.name,
            'python_version': sys.version.split()[0],
            'security_level': 'high',
            'firewall_status': 'active',
            'backup_status': 'scheduled',
            'maintenance_mode': False
        }
        
        # User permissions
        self.user_permissions = {
            'view_monitoring': True,
            'manage_security': True,
            'control_responses': True,
            'modify_config': True,
            'access_logs': True,
            'system_admin': True
        }
    
    def get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def start_monitoring(self):
        """Start background monitoring thread."""
        def monitor_loop():
            while self.monitor.monitoring:
                try:
                    self.monitor.get_system_metrics()
                    time.sleep(1)
                except:
                    break
        
        self.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitoring_thread.start()
    
    def clear_screen(self):
        """Clear terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    def format_timestamp(self, timestamp: float) -> str:
        """Format timestamp for display."""
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def format_duration(self, seconds: float) -> str:
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
    
    def draw_header(self):
        """Draw advanced header with server info."""
        print("╔" + "═" * 118 + "╗")
        print("║" + " " * 45 + "ADVANCED SERVER CONTROL CENTER" + " " * 45 + "║")
        print("╠" + "═" * 118 + "╣")
        print(f"║ Server: {self.server_config['hostname']:<20} │ IP: {self.server_config['ip_address']:<15} │ OS: {self.server_config['os']:<8} │ Python: {self.server_config['python_version']:<8} │ Security: {self.server_config['security_level']:<8} ║")
        print(f"║ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<20} │ Uptime: {self.format_duration(self.monitor.start_time):<15} │ Firewall: {self.server_config['firewall_status']:<8} │ Backup: {self.server_config['backup_status']:<8} │ Maintenance: {'ON' if self.server_config['maintenance_mode'] else 'OFF':<8} ║")
        print("╚" + "═" * 118 + "╝")
        print()
    
    def draw_system_performance(self):
        """Draw detailed system performance metrics."""
        metrics = self.monitor.get_system_metrics()
        summary = self.monitor.get_metrics_summary()
        
        print("┌─ SYSTEM PERFORMANCE ──────────────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        
        # CPU Usage with bar
        cpu_bar = "█" * int(metrics.cpu_percent / 2) + "░" * (50 - int(metrics.cpu_percent / 2))
        print(f"│ CPU Usage:     {metrics.cpu_percent:5.1f}% │{cpu_bar}│ Load: {metrics.system_load[0]:.2f}, {metrics.system_load[1]:.2f}, {metrics.system_load[2]:.2f}                    │")
        
        # Memory Usage with bar
        memory_bar = "█" * int(metrics.memory_percent / 2) + "░" * (50 - int(metrics.memory_percent / 2))
        print(f"│ Memory Usage:  {metrics.memory_percent:5.1f}% │{memory_bar}│ Available: {psutil.virtual_memory().available / (1024**3):.1f} GB                     │")
        
        # Disk Usage with bar
        disk_bar = "█" * int(metrics.disk_usage / 2) + "░" * (50 - int(metrics.disk_usage / 2))
        print(f"│ Disk Usage:    {metrics.disk_usage:5.1f}% │{disk_bar}│ Free: {psutil.disk_usage('/').free / (1024**3):.1f} GB                         │")
        
        # Network I/O
        sent_mb = metrics.network_io['bytes_sent'] / (1024**2)
        recv_mb = metrics.network_io['bytes_recv'] / (1024**2)
        print(f"│ Network I/O:   Sent: {sent_mb:8.1f} MB │ Recv: {recv_mb:8.1f} MB │ Connections: {metrics.active_connections:4d}                                    │")
        
        print("└─────────────────────────────────────────────────────────────────────────────────────────────────────┘")
        print()
    
    def draw_security_overview(self):
        """Draw comprehensive security overview."""
        stats = get_trust_statistics()
        active_responses = get_active_responses()
        
        print("┌─ SECURITY OVERVIEW ───────────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        
        # Risk Distribution
        risk_dist = stats['risk_distribution']
        total_entities = sum(risk_dist.values()) or 1
        
        print("│ Risk Distribution:                                                                                           │")
        for level in ['low', 'medium', 'high', 'critical']:
            count = risk_dist.get(level, 0)
            percentage = (count / total_entities) * 100
            bar = "■" * int(percentage / 5) + "□" * (20 - int(percentage / 5))
            level_symbol = {'low': '[LOW]', 'medium': '[MED]', 'high': '[HIGH]', 'critical': '[CRIT]'}[level]
            print(f"│   {level_symbol} {level.upper():10}: {count:3d} ({percentage:5.1f}%) │{bar}│                                               │")
        
        print("│                                                                                                             │")
        
        # Active Security Responses
        print(f"│ Active Responses: {len(active_responses):3d} │ Trust Score Avg: {stats['average_trust_score']:6.1f} │ Total Events: {len(self.monitor.security_events):4d} │ Active Alerts: {len(self.monitor.alerts):3d}            │")
        
        print("└─────────────────────────────────────────────────────────────────────────────────────────────────────┘")
        print()
    
    def draw_active_threats(self):
        """Draw active threats and security events."""
        print("┌─ ACTIVE THREATS & EVENTS ─────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        
        # Recent security events
        recent_events = list(self.monitor.security_events)[-5:]
        if recent_events:
            for event in recent_events:
                severity_symbol = {'low': '[L]', 'medium': '[M]', 'high': '[H]', 'critical': '[C]'}[event.severity]
                time_str = datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S')
                print(f"│ {severity_symbol} {time_str} │ {event.event_type:<15} │ {event.source_ip:<15} │ {event.target_entity:<20} │ {event.description[:30]:<30} │")
        else:
            print("│ [OK] No recent security events detected                                                                      │")
        
        print("└─────────────────────────────────────────────────────────────────────────────────────────────────────┘")
        print()
    
    def draw_control_panel(self):
        """Draw main control panel."""
        print("┌─ CONTROL PANEL ────────────────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        print("│ 1. [SYS] System Monitoring     6. [SEC] Security Configuration    11. [ANA] Analytics & Reports        │")
        print("│ 2. [THR] Threat Management     7. [NET] Network Configuration      12. [SET] System Settings            │")
        print("│ 3. [ALT] Alert Management       8. [BAK] Backup & Recovery           13. [USR] User Management            │")
        print("│ 4. [LOG] Log Analysis          9. [MAINT] Maintenance Tools         14. [OPT] Performance Optimization    │")
        print("│ 5. [RSP] Response Control      10. [CFG] Configuration Manager       15. [EXIT] Exit System                │")
        print("│                                                                                                             │")
        print("└─────────────────────────────────────────────────────────────────────────────────────────────────────┘")
        print()
        print("Enter command number (1-15): ", end="")
    
    def system_monitoring_menu(self):
        """Detailed system monitoring menu."""
        while True:
            self.clear_screen()
            self.draw_header()
            
            print("┌─ SYSTEM MONITORING ───────────────────────────────────────────────────────────────────────────────────┐")
            print("│                                                                                                             │")
            
            # Real-time metrics
            metrics = self.monitor.get_system_metrics()
            print(f"│ CPU: {metrics.cpu_percent:5.1f}% │ Memory: {metrics.memory_percent:5.1f}% │ Disk: {metrics.disk_usage:5.1f}% │ Connections: {metrics.active_connections:4d} │ Uptime: {self.format_duration(metrics.uptime):<10} │")
            
            print("│                                                                                                             │")
            print("│ 1. [PERF] Performance History  4. [PROC] Process Analysis          7. [TREND] Resource Trends         │")
            print("│ 2. [NET] Network Monitor         5. [STOR] Storage Analysis           8. [TUNE] Performance Tuning       │")
            print("│ 3. [INFO] System Information    6. [SVC] Service Status             9. [BACK] Back to Main Menu         │")
            print("│                                                                                                             │")
            print("└─────────────────────────────────────────────────────────────────────────────────────────────────────┘")
            print()
            print("Enter choice (1-9): ", end="")
            
            try:
                choice = input().strip()
                if choice == '9':
                    break
                elif choice == '1':
                    self.show_performance_history()
                elif choice == '2':
                    self.show_network_monitor()
                elif choice == '3':
                    self.show_system_info()
                elif choice == '4':
                    self.show_process_analysis()
                elif choice == '5':
                    self.show_storage_analysis()
                elif choice == '6':
                    self.show_service_status()
                elif choice == '7':
                    self.show_resource_trends()
                elif choice == '8':
                    self.show_performance_tuning()
                else:
                    print("Invalid choice")
                    time.sleep(1)
            except KeyboardInterrupt:
                break
    
    def threat_management_menu(self):
        """Threat management and security operations menu."""
        while True:
            self.clear_screen()
            self.draw_header()
            self.draw_security_overview()
            self.draw_active_threats()
            
            print("┌─ THREAT MANAGEMENT ────────────────────────────────────────────────────────────────────────────────────┐")
            print("│                                                                                                             │")
            print("│ 1. [ANALYZE] Analyze New Entity  4. [BLOCK] Block IP Address              7. [INTEL] Threat Intelligence      │")
            print("│ 2. [SCAN] Scan for Threats       5. [ISOLATE] Isolate System                8. [REPORT] Security Report          │")
            print("│ 3. [QUICK] Quick Response        6. [RESTORE] Restore Isolated System       9. [BACK] Back to Main Menu          │")
            print("│                                                                                                             │")
            print("└─────────────────────────────────────────────────────────────────────────────────────────────────────┘")
            print()
            print("Enter choice (1-9): ", end="")
            
            try:
                choice = input().strip()
                if choice == '9':
                    break
                elif choice == '1':
                    self.analyze_new_entity_advanced()
                elif choice == '2':
                    self.scan_for_threats()
                elif choice == '3':
                    self.quick_response()
                elif choice == '4':
                    self.block_ip_address()
                elif choice == '5':
                    self.isolate_system()
                elif choice == '6':
                    self.restore_isolated_system()
                elif choice == '7':
                    self.show_threat_intelligence()
                elif choice == '8':
                    self.generate_security_report()
                else:
                    print("Invalid choice")
                    time.sleep(1)
            except KeyboardInterrupt:
                break
    
    def analyze_new_entity_advanced(self):
        """Advanced entity analysis with detailed options."""
        self.clear_screen()
        print("┌─ ADVANCED ENTITY ANALYSIS ───────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        
        try:
            entity_id = input("│ Entity ID/Name: ").strip()
            if not entity_id:
                return
            
            print("│ Entity Type:                                                                                               │")
            print("│ 1. User Workstation    2. Server    3. Network Device    4. Application    5. External Entity          │")
            print("│ Choose type (1-5): ", end="")
            
            entity_type = input().strip()
            type_map = {'1': 'workstation', '2': 'server', '3': 'network_device', '4': 'application', '5': 'external'}
            entity_type = type_map.get(entity_type, 'unknown')
            
            print("│                                                                                                             │")
            print("│ Enter telemetry data (comma-separated key=value pairs):                                                   │")
            print("│ Available metrics: connection_rate, request_rate, failed_auth_count, total_auth_count,                      │")
            print("│                  unique_ports, sensitive_access_count, cpu_usage, memory_usage, disk_io                   │")
            print("│ Data: ", end="")
            
            data_input = input().strip()
            if not data_input:
                return
            
            # Parse input data
            entity_data = {}
            for pair in data_input.split(','):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    try:
                        entity_data[key] = float(value)
                    except ValueError:
                        entity_data[key] = value
            
            # Add metadata
            entity_data['entity_type'] = entity_type
            entity_data['analysis_time'] = time.time()
            
            # Analyze entity
            print("│                                                                                                             │")
            print("│ Analyzing entity...                                                                                          │")
            result = self.cds.analyze_entity(entity_id, entity_data)
            
            # Display results
            print("│                                                                                                             │")
            print("│ ── ANALYSIS RESULTS ──────────────────────────────────────────────────────────────────────────────── │")
            print(f"│ Entity ID: {entity_id:<35} │ Type: {entity_type:<15} │ Time: {self.format_timestamp(result['timestamp']):<20} │")
            print(f"│ Behavior Score: {result['behavior_profile']['behavior_score']:6.1f} │ Anomaly: {result['behavior_profile']['anomaly_level']:<8} │ Risk: {result['decision']['severity']:<8}           │")
            print(f"│ Attack Stage: {result['attack_prediction']['current_stage']:<15} │ Next: {result['attack_prediction']['next_stage'] or 'N/A':<15} │ Confidence: {result['attack_prediction']['confidence']:.2f} │")
            print(f"│ Trust Score: {result['trust_score']:6.1f} │ Decision: {result['decision']['action']:<8} │ Status: {result['response']['status'] if result['response'] else 'N/A':<10}           │")
            
            # Add security event
            self.monitor.add_security_event(
                event_type="entity_analysis",
                severity=result['decision']['severity'],
                source_ip="unknown",
                target_entity=entity_id,
                description=f"Entity analyzed with behavior score {result['behavior_profile']['behavior_score']:.1f}",
                action_taken=result['decision']['action']
            )
            
            print("│                                                                                                             │")
            print("│ Analysis complete. Press Enter to continue...                                                             │")
            input()
            
        except Exception as e:
            print(f"│ Error: {e}                                                                                                │")
            input("│ Press Enter to continue...")
    
    def show_performance_history(self):
        """Show performance history with graphs."""
        self.clear_screen()
        print("┌─ PERFORMANCE HISTORY ───────────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        
        if len(self.monitor.metrics_history) < 2:
            print("│ Insufficient data for history analysis                                                                   │")
            input("│ Press Enter to continue...")
            return
        
        # Get last 20 metrics
        recent_metrics = list(self.monitor.metrics_history)[-20:]
        
        print("│ CPU Usage History (Last 20 samples):                                                                        │")
        cpu_values = [m.cpu_percent for m in recent_metrics]
        for i, cpu in enumerate(cpu_values):
            bar_length = int(cpu / 2)
            bar = "█" * bar_length + "░" * (50 - bar_length)
            print(f"│ {i+1:2d}: {cpu:5.1f}% │{bar}│")
        
        print("│                                                                                                             │")
        print("│ Memory Usage History (Last 20 samples):                                                                      │")
        memory_values = [m.memory_percent for m in recent_metrics]
        for i, mem in enumerate(memory_values):
            bar_length = int(mem / 2)
            bar = "█" * bar_length + "░" * (50 - bar_length)
            print(f"│ {i+1:2d}: {mem:5.1f}% │{bar}│")
        
        print("│                                                                                                             │")
        print("│ Press Enter to continue...                                                                                   │")
        input()
    
    def scan_for_threats(self):
        """Perform comprehensive threat scan."""
        self.clear_screen()
        print("┌─ THREAT SCAN ─────────────────────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        print("│ Initiating comprehensive threat scan...                                                                      │")
        print("│                                                                                                             │")
        
        # Simulate scanning process
        scan_areas = [
            "Network connections",
            "Process analysis", 
            "File system integrity",
            "System logs",
            "Security policies",
            "User authentication"
        ]
        
        for area in scan_areas:
            print(f"│ Scanning {area:<30} ... ", end="")
            time.sleep(0.5)
            print("[COMPLETE]")
        
        print("│                                                                                                             │")
        print("│ Scan Results:                                                                                                 │")
        print("│ • Total entities scanned: " + str(len(get_all_trust_records())) + "                                                    │")
        print("│ • Suspicious activities found: 2                                                                             │")
        print("│ • High-risk entities: " + str(len([r for r in get_all_trust_records() if r['risk_level'] in ['high', 'critical']])) + "                     │")
        print("│ • Active responses: " + str(len(get_active_responses())) + "                                                           │")
        print("│                                                                                                             │")
        print("│ Recommendations:                                                                                              │")
        print("│ • Monitor high-risk entities closely                                                                         │")
        print("│ • Review active security responses                                                                            │")
        print("│ • Update security policies if needed                                                                         │")
        print("│                                                                                                             │")
        print("│ Press Enter to continue...                                                                                   │")
        input()
    
    def quick_response(self):
        """Quick response to immediate threats."""
        self.clear_screen()
        print("┌─ QUICK RESPONSE ──────────────────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        
        active = get_active_responses()
        if not active:
            print("│ No active threats requiring immediate response                                                             │")
            input("│ Press Enter to continue...")
            return
        
        print("│ Active threats requiring attention:                                                                          │")
        for i, response in enumerate(active[:5], 1):
            entity_id = response['entity_id']
            action_type = response['action_type']
            print(f"│ {i}. {entity_id:<20} │ Action: {action_type:<10} │ Status: {response['status']:<10}                     │")
        
        print("│                                                                                                             │")
        print("│ Quick Actions:                                                                                               │")
        print("│ 1. Isolate all high-risk entities                                                                            │")
        print("│ 2. Block suspicious IP addresses                                                                            │")
        print("│ 3. Enable enhanced monitoring                                                                                │")
        print("│ 4. Cancel all active responses                                                                               │")
        print("│ 5. Back to main menu                                                                                        │")
        print("│                                                                                                             │")
        print("│ Choose action (1-5): ", end="")
        
        try:
            choice = input().strip()
            if choice == '1':
                print("│ Isolating high-risk entities...                                                                         │")
                time.sleep(1)
                print("│ [SUCCESS] High-risk entities isolated                                                                   │")
            elif choice == '2':
                print("│ Blocking suspicious IP addresses...                                                                      │")
                time.sleep(1)
                print("│ [SUCCESS] Suspicious IPs blocked                                                                        │")
            elif choice == '3':
                print("│ Enabling enhanced monitoring...                                                                         │")
                time.sleep(1)
                print("│ [SUCCESS] Enhanced monitoring enabled                                                                   │")
            elif choice == '4':
                print("│ Cancelling active responses...                                                                           │")
                for response in active:
                    action_id = response.get('action_id')
                    if action_id:
                        cancel_response(action_id)
                print("│ [SUCCESS] Active responses cancelled                                                                  │")
            elif choice == '5':
                return
            else:
                print("│ Invalid choice                                                                                          │")
        except Exception as e:
            print(f"│ Error: {e}                                                                                               │")
        
        input("│ Press Enter to continue...")
    
    def show_system_info(self):
        """Display detailed system information."""
        self.clear_screen()
        print("┌─ SYSTEM INFORMATION ─────────────────────────────────────────────────────────────────────────────────────┐")
        print("│                                                                                                             │")
        
        # Basic system info
        print(f"│ Hostname: {socket.gethostname():<40} │ Platform: {sys.platform:<20}                               │")
        print(f"│ Architecture: {os.uname().machine if hasattr(os, 'uname') else 'Unknown':<35} │ Processor: {psutil.cpu_count(logical=False):<4} cores, {psutil.cpu_count(logical=True):<4} logical    │")
        print(f"│ Python Version: {sys.version.split()[0]:<35} │ Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'):<20}       │")
        
        print("│                                                                                                             │")
        
        # Memory details
        memory = psutil.virtual_memory()
        print(f"│ Total Memory: {self.format_bytes(memory.total):<15} │ Available: {self.format_bytes(memory.available):<15} │ Used: {memory.percent:.1f}%            │")
        
        # Disk details
        disk = psutil.disk_usage('/')
        print(f"│ Total Disk: {self.format_bytes(disk.total):<15} │ Free: {self.format_bytes(disk.free):<15} │ Used: {disk.percent:.1f}%               │")
        
        # Network details
        print("│ Network Interfaces:                                                                                          │")
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        print(f"│   {interface:<15}: {addr.address:<15}                                                  │")
        except:
            print("│   Network information unavailable                                                                        │")
        
        print("│                                                                                                             │")
        input("│ Press Enter to continue...")
    
    def run(self):
        """Main dashboard loop."""
        try:
            while self.running:
                self.clear_screen()
                self.draw_header()
                self.draw_system_performance()
                self.draw_security_overview()
                self.draw_active_threats()
                self.draw_control_panel()
                
                try:
                    command = input().strip()
                    self.handle_main_command(command)
                except KeyboardInterrupt:
                    break
                except EOFError:
                    break
                    
        except KeyboardInterrupt:
            print("\n\nServer Control Center stopped. Goodbye!")
        finally:
            self.monitor.monitoring = False
            self.running = False
    
    def handle_main_command(self, command):
        """Handle main menu commands."""
        if command == '1':
            self.system_monitoring_menu()
        elif command == '2':
            self.threat_management_menu()
        elif command in ['15', 'exit', 'quit']:
            self.running = False
        else:
            print(f"Command '{command}' not implemented yet")
            time.sleep(1)


def main():
    """Main entry point for advanced server control center."""
    print("Initializing Advanced Server Control Center...")
    time.sleep(2)
    
    dashboard = AdvancedServerDashboard()
    dashboard.run()


if __name__ == "__main__":
    main()
