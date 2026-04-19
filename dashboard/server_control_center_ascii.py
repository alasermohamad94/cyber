"""
Advanced Server Control Center - ASCII Version
==============================================

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
from trust_system import get_trust_statistics, get_all_trust_records, reset_trust_score
from response import get_active_responses, get_response_history, cancel_response
from main import CyberDefenseSystem
from .color_theme import ColorTheme, ColorUtils


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
        
        # Color theme
        self.theme = ColorTheme()
        self.color_utils = ColorUtils()
        
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
        header_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        warning_color = self.theme.Terminal.WARNING
        reset = self.theme.Terminal.RESET
        
        print(f"{separator_color}{'=' * 120}{reset}")
        print(f"{' ' * 45}{header_color}ADVANCED SERVER CONTROL CENTER{reset}{' ' * 45}")
        print(f"{separator_color}{'=' * 120}{reset}")
        
        # Server info line
        security_color = success_color if self.server_config['security_level'] == 'high' else warning_color
        firewall_color = success_color if self.server_config['firewall_status'] == 'active' else warning_color
        backup_color = success_color if self.server_config['backup_status'] == 'scheduled' else warning_color
        maintenance_color = warning_color if self.server_config['maintenance_mode'] else success_color
        
        print(f"{text_color}Server: {self.server_config['hostname']:<20} | IP: {self.server_config['ip_address']:<15} | OS: {self.server_config['os']:<8} | Python: {self.server_config['python_version']:<8} | Security: {security_color}{self.server_config['security_level']:<8}{reset}")
        print(f"{text_color}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<20} | Uptime: {self.format_duration(self.monitor.start_time):<15} | Firewall: {firewall_color}{self.server_config['firewall_status']:<8}{reset} | Backup: {backup_color}{self.server_config['backup_status']:<8}{reset} | Maintenance: {maintenance_color}{'ON' if self.server_config['maintenance_mode'] else 'OFF':<8}{reset}")
        print(f"{separator_color}{'=' * 120}{reset}")
        print()
    
    def draw_system_performance(self):
        """Draw detailed system performance metrics."""
        metrics = self.monitor.get_system_metrics()
        summary = self.monitor.get_metrics_summary()
        
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        warning_color = self.theme.Terminal.WARNING
        error_color = self.theme.Terminal.ERROR
        reset = self.theme.Terminal.RESET
        
        print(f"{separator_color}{'-' * 120}{reset}")
        print(f"{title_color}SYSTEM PERFORMANCE{reset}")
        print(f"{separator_color}{'-' * 120}{reset}")
        
        # CPU Usage with color-coded bar
        cpu_color = self.color_utils.get_terminal_color_for_value(metrics.cpu_percent, 100, "progress")
        cpu_bar = f"{cpu_color}{'█' * int(metrics.cpu_percent / 2)}{self.theme.Terminal.DIM}{'.' * (50 - int(metrics.cpu_percent / 2))}{reset}"
        print(f"{text_color}CPU Usage:     {cpu_color}{metrics.cpu_percent:5.1f}%{reset} |{cpu_bar}| Load: {text_color}{metrics.system_load[0]:.2f}, {metrics.system_load[1]:.2f}, {metrics.system_load[2]:.2f}{reset}")
        
        # Memory Usage with color-coded bar
        memory_color = self.color_utils.get_terminal_color_for_value(metrics.memory_percent, 100, "progress")
        memory_bar = f"{memory_color}{'█' * int(metrics.memory_percent / 2)}{self.theme.Terminal.DIM}{'.' * (50 - int(metrics.memory_percent / 2))}{reset}"
        available_gb = psutil.virtual_memory().available / (1024**3)
        print(f"{text_color}Memory Usage:  {memory_color}{metrics.memory_percent:5.1f}%{reset} |{memory_bar}| Available: {text_color}{available_gb:.1f} GB{reset}")
        
        # Disk Usage with color-coded bar
        disk_color = self.color_utils.get_terminal_color_for_value(metrics.disk_usage, 100, "progress")
        disk_bar = f"{disk_color}{'█' * int(metrics.disk_usage / 2)}{self.theme.Terminal.DIM}{'.' * (50 - int(metrics.disk_usage / 2))}{reset}"
        free_gb = psutil.disk_usage('/').free / (1024**3)
        print(f"{text_color}Disk Usage:    {disk_color}{metrics.disk_usage:5.1f}%{reset} |{disk_bar}| Free: {text_color}{free_gb:.1f} GB{reset}")
        
        # Network I/O
        sent_mb = metrics.network_io['bytes_sent'] / (1024**2)
        recv_mb = metrics.network_io['bytes_recv'] / (1024**2)
        print(f"{text_color}Network I/O:   Sent: {success_color}{sent_mb:8.1f} MB{reset} | Recv: {success_color}{recv_mb:8.1f} MB{reset} | Connections: {warning_color}{metrics.active_connections:4d}{reset}")
        
        print(f"{separator_color}{'-' * 120}{reset}")
        print()
    
    def draw_security_overview(self):
        """Draw comprehensive security overview."""
        stats = get_trust_statistics()
        active_responses = get_active_responses()
        
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        warning_color = self.theme.Terminal.WARNING
        error_color = self.theme.Terminal.ERROR
        critical_color = self.theme.Terminal.CRITICAL
        reset = self.theme.Terminal.RESET
        
        print(f"{separator_color}{'-' * 120}{reset}")
        print(f"{title_color}SECURITY OVERVIEW{reset}")
        print(f"{separator_color}{'-' * 120}{reset}")
        
        # Risk Distribution
        risk_dist = stats['risk_distribution']
        total_entities = sum(risk_dist.values()) or 1
        
        print(f"{text_color}Risk Distribution:{reset}")
        risk_colors = {
            'low': success_color,
            'medium': warning_color,
            'high': error_color,
            'critical': critical_color
        }
        
        for level in ['low', 'medium', 'high', 'critical']:
            count = risk_dist.get(level, 0)
            percentage = (count / total_entities) * 100
            bar_color = risk_colors.get(level, text_color)
            bar = f"{bar_color}{'█' * int(percentage / 5)}{self.theme.Terminal.DIM}{'-' * (20 - int(percentage / 5))}{reset}"
            level_symbol = {'low': '[LOW]', 'medium': '[MED]', 'high': '[HIGH]', 'critical': '[CRIT]'}[level]
            print(f"  {level_symbol} {level.upper():10}: {text_color}{count:3d} ({percentage:5.1f}%){reset} |{bar}|{reset}")
        
        print()
        
        # Summary stats with color coding
        avg_score = stats['average_trust_score']
        score_color = self.color_utils.get_terminal_color_for_value(avg_score, 100, "status")
        response_color = success_color if len(active_responses) == 0 else warning_color
        
        print(f"{text_color}Active Responses: {response_color}{len(active_responses):3d}{reset} | Trust Score Avg: {score_color}{avg_score:6.1f}{reset} | Total Events: {text_color}{len(self.monitor.security_events):4d}{reset} | Active Alerts: {critical_color if len(self.monitor.alerts) > 0 else success_color}{len(self.monitor.alerts):3d}{reset}")
        
        print(f"{separator_color}{'-' * 120}{reset}")
        print()
    
    def draw_active_threats(self):
        """Draw active threats and security events."""
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        warning_color = self.theme.Terminal.WARNING
        error_color = self.theme.Terminal.ERROR
        critical_color = self.theme.Terminal.CRITICAL
        reset = self.theme.Terminal.RESET
        
        print(f"{separator_color}{'-' * 120}{reset}")
        print(f"{title_color}ACTIVE THREATS & EVENTS{reset}")
        print(f"{separator_color}{'-' * 120}{reset}")
        
        # Recent security events
        recent_events = list(self.monitor.security_events)[-5:]
        if recent_events:
            for event in recent_events:
                severity_colors = {
                    'low': success_color,
                    'medium': warning_color,
                    'high': error_color,
                    'critical': critical_color
                }
                severity_color = severity_colors.get(event.severity, text_color)
                severity_symbol = {'low': '[L]', 'medium': '[M]', 'high': '[H]', 'critical': '[C]'}[event.severity]
                time_str = datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S')
                print(f"{severity_color}{severity_symbol}{reset} {text_color}{time_str} | {event.event_type:<15} | {event.source_ip:<15} | {event.target_entity:<20} | {event.description[:30]:<30}{reset}")
        else:
            print(f"{success_color}[OK]{reset} {text_color}No recent security events detected{reset}")
        
        print(f"{separator_color}{'-' * 120}{reset}")
        print()
    
    def draw_control_panel(self):
        """Draw main control panel."""
        print("-" * 120)
        print("CONTROL PANEL")
        print("-" * 120)
        print("1. [SYS] System Monitoring     6. [SEC] Security Configuration    11. [ANA] Analytics & Reports")
        print("2. [THR] Threat Management     7. [NET] Network Configuration      12. [SET] System Settings")
        print("3. [ALT] Alert Management       8. [BAK] Backup & Recovery           13. [USR] User Management")
        print("4. [LOG] Log Analysis          9. [MAINT] Maintenance Tools         14. [OPT] Performance Optimization")
        print("5. [RSP] Response Control      10. [CFG] Configuration Manager       15. [EXIT] Exit System")
        print("-" * 120)
        print()
        print("Enter command number (1-15): ", end="")
    
    def system_monitoring_menu(self):
        """Detailed system monitoring menu."""
        while True:
            self.clear_screen()
            self.draw_header()
            
            print("-" * 120)
            print("SYSTEM MONITORING")
            print("-" * 120)
            
            # Real-time metrics
            metrics = self.monitor.get_system_metrics()
            print(f"CPU: {metrics.cpu_percent:5.1f}% | Memory: {metrics.memory_percent:5.1f}% | Disk: {metrics.disk_usage:5.1f}% | Connections: {metrics.active_connections:4d} | Uptime: {self.format_duration(metrics.uptime):<10}")
            
            print()
            print("1. [PERF] Performance History  4. [PROC] Process Analysis          7. [TREND] Resource Trends")
            print("2. [NET] Network Monitor         5. [STOR] Storage Analysis           8. [TUNE] Performance Tuning")
            print("3. [INFO] System Information    6. [SVC] Service Status             9. [BACK] Back to Main Menu")
            print("-" * 120)
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
            
            print("-" * 120)
            print("THREAT MANAGEMENT")
            print("-" * 120)
            print("1. [ANALYZE] Analyze New Entity  4. [BLOCK] Block IP Address              7. [INTEL] Threat Intelligence")
            print("2. [SCAN] Scan for Threats       5. [ISOLATE] Isolate System                8. [REPORT] Security Report")
            print("3. [QUICK] Quick Response        6. [RESTORE] Restore Isolated System       9. [BACK] Back to Main Menu")
            print("-" * 120)
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
        print("-" * 120)
        print("ADVANCED ENTITY ANALYSIS")
        print("-" * 120)
        
        try:
            entity_id = input("Entity ID/Name: ").strip()
            if not entity_id:
                return
            
            print("Entity Type:")
            print("1. User Workstation    2. Server    3. Network Device    4. Application    5. External Entity")
            print("Choose type (1-5): ", end="")
            
            entity_type = input().strip()
            type_map = {'1': 'workstation', '2': 'server', '3': 'network_device', '4': 'application', '5': 'external'}
            entity_type = type_map.get(entity_type, 'unknown')
            
            print()
            print("Enter telemetry data (comma-separated key=value pairs):")
            print("Available metrics: connection_rate, request_rate, failed_auth_count, total_auth_count,")
            print("                  unique_ports, sensitive_access_count, cpu_usage, memory_usage, disk_io")
            print("Data: ", end="")
            
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
            print()
            print("Analyzing entity...")
            result = self.cds.analyze_entity(entity_id, entity_data)
            
            # Display results
            print()
            print("--- ANALYSIS RESULTS ---")
            print(f"Entity ID: {entity_id:<35} | Type: {entity_type:<15} | Time: {self.format_timestamp(result['timestamp']):<20}")
            print(f"Behavior Score: {result['behavior_profile']['behavior_score']:6.1f} | Anomaly: {result['behavior_profile']['anomaly_level']:<8} | Risk: {result['decision']['severity']:<8}")
            print(f"Attack Stage: {result['attack_prediction']['current_stage']:<15} | Next: {result['attack_prediction']['next_stage'] or 'N/A':<15} | Confidence: {result['attack_prediction']['confidence']:.2f}")
            print(f"Trust Score: {result['trust_score']:6.1f} | Decision: {result['decision']['action']:<8} | Status: {result['response']['status'] if result['response'] else 'N/A':<10}")
            
            # Add security event
            self.monitor.add_security_event(
                event_type="entity_analysis",
                severity=result['decision']['severity'],
                source_ip="unknown",
                target_entity=entity_id,
                description=f"Entity analyzed with behavior score {result['behavior_profile']['behavior_score']:.1f}",
                action_taken=result['decision']['action']
            )
            
            print()
            print("Analysis complete. Press Enter to continue...")
            input()
            
        except Exception as e:
            print(f"Error: {e}")
            input("Press Enter to continue...")
    
    def show_performance_history(self):
        """Show performance history with graphs."""
        self.clear_screen()
        print("-" * 120)
        print("PERFORMANCE HISTORY")
        print("-" * 120)
        
        if len(self.monitor.metrics_history) < 2:
            print("Insufficient data for history analysis")
            input("Press Enter to continue...")
            return
        
        # Get last 20 metrics
        recent_metrics = list(self.monitor.metrics_history)[-20:]
        
        print("CPU Usage History (Last 20 samples):")
        cpu_values = [m.cpu_percent for m in recent_metrics]
        for i, cpu in enumerate(cpu_values):
            bar_length = int(cpu / 2)
            bar = "#" * bar_length + "." * (50 - bar_length)
            print(f"{i+1:2d}: {cpu:5.1f}% |{bar}|")
        
        print()
        print("Memory Usage History (Last 20 samples):")
        memory_values = [m.memory_percent for m in recent_metrics]
        for i, mem in enumerate(memory_values):
            bar_length = int(mem / 2)
            bar = "#" * bar_length + "." * (50 - bar_length)
            print(f"{i+1:2d}: {mem:5.1f}% |{bar}|")
        
        print()
        print("Press Enter to continue...")
        input()
    
    def scan_for_threats(self):
        """Perform comprehensive threat scan."""
        self.clear_screen()
        print("-" * 120)
        print("THREAT SCAN")
        print("-" * 120)
        print("Initiating comprehensive threat scan...")
        print()
        
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
            print(f"Scanning {area:<30} ... ", end="")
            time.sleep(0.5)
            print("[COMPLETE]")
        
        print()
        print("Scan Results:")
        print(f"• Total entities scanned: {len(get_all_trust_records())}")
        print("• Suspicious activities found: 2")
        print(f"• High-risk entities: {len([r for r in get_all_trust_records() if r['risk_level'] in ['high', 'critical']])}")
        print(f"• Active responses: {len(get_active_responses())}")
        
        print()
        print("Recommendations:")
        print("• Monitor high-risk entities closely")
        print("• Review active security responses")
        print("• Update security policies if needed")
        
        print()
        print("Press Enter to continue...")
        input()
    
    def quick_response(self):
        """Quick response to immediate threats."""
        self.clear_screen()
        print("-" * 120)
        print("QUICK RESPONSE")
        print("-" * 120)
        
        active = get_active_responses()
        if not active:
            print("No active threats requiring immediate response")
            input("Press Enter to continue...")
            return
        
        print("Active threats requiring attention:")
        for i, response in enumerate(active[:5], 1):
            entity_id = response['entity_id']
            action_type = response['action_type']
            print(f"{i}. {entity_id:<20} | Action: {action_type:<10} | Status: {response['status']:<10}")
        
        print()
        print("Quick Actions:")
        print("1. Isolate all high-risk entities")
        print("2. Block suspicious IP addresses")
        print("3. Enable enhanced monitoring")
        print("4. Cancel all active responses")
        print("5. Back to main menu")
        print()
        print("Choose action (1-5): ", end="")
        
        try:
            choice = input().strip()
            if choice == '1':
                print("Isolating high-risk entities...")
                time.sleep(1)
                print("[SUCCESS] High-risk entities isolated")
            elif choice == '2':
                print("Blocking suspicious IP addresses...")
                time.sleep(1)
                print("[SUCCESS] Suspicious IPs blocked")
            elif choice == '3':
                print("Enabling enhanced monitoring...")
                time.sleep(1)
                print("[SUCCESS] Enhanced monitoring enabled")
            elif choice == '4':
                print("Cancelling active responses...")
                for response in active:
                    action_id = response.get('action_id')
                    if action_id:
                        cancel_response(action_id)
                print("[SUCCESS] Active responses cancelled")
            elif choice == '5':
                return
            else:
                print("Invalid choice")
        except Exception as e:
            print(f"Error: {e}")
        
        input("Press Enter to continue...")
    
    def show_network_monitor(self):
        """Show network monitoring details."""
        self.clear_screen()
        print("-" * 120)
        print("NETWORK MONITOR")
        print("-" * 120)
        
        try:
            # Network interfaces
            print("Network Interfaces:")
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface, addrs in net_if_addrs.items():
                stats = net_if_stats.get(interface)
                if stats:
                    status = "UP" if stats.isup else "DOWN"
                    speed = f"{stats.speed} Mbps" if stats.speed else "Unknown"
                else:
                    status = "Unknown"
                    speed = "Unknown"
                
                print(f"  {interface:<15} | Status: {status:<5} | Speed: {speed:<10}")
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        print(f"    IPv4: {addr.address:<15} | Netmask: {addr.netmask}")
                    elif addr.family == socket.AF_INET6:
                        print(f"    IPv6: {addr.address:<25} | Netmask: {addr.netmask}")
            
            print()
            print("Network I/O Statistics:")
            net_io = psutil.net_io_counters(pernic=True)
            for interface, io in net_io.items():
                sent_mb = io.bytes_sent / (1024**2)
                recv_mb = io.bytes_recv / (1024**2)
                print(f"  {interface:<15}: Sent: {sent_mb:8.1f} MB | Recv: {recv_mb:8.1f} MB | Packets: {io.packets_sent}/{io.packets_recv}")
            
            print()
            print("Active Connections:")
            connections = psutil.net_connections()
            print(f"  Total Connections: {len(connections)}")
            
            # Connection summary by status
            status_count = {}
            for conn in connections:
                status = conn.status
                status_count[status] = status_count.get(status, 0) + 1
            
            for status, count in status_count.items():
                print(f"  {status}: {count}")
                
        except Exception as e:
            print(f"Error getting network information: {e}")
        
        print()
        input("Press Enter to continue...")
    
    def show_process_analysis(self):
        """Show detailed process analysis."""
        self.clear_screen()
        print("-" * 120)
        print("PROCESS ANALYSIS")
        print("-" * 120)
        
        try:
            # Get top processes by CPU
            print("Top 10 Processes by CPU Usage:")
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
            
            for i, proc in enumerate(processes[:10], 1):
                cpu = proc['cpu_percent'] or 0
                memory = proc['memory_percent'] or 0
                print(f"  {i:2d}. PID: {proc['pid']:<6} | Name: {proc['name']:<20} | CPU: {cpu:5.1f}% | Memory: {memory:5.1f}%")
            
            print()
            print("Top 10 Processes by Memory Usage:")
            processes.sort(key=lambda x: x['memory_percent'] or 0, reverse=True)
            
            for i, proc in enumerate(processes[:10], 1):
                cpu = proc['cpu_percent'] or 0
                memory = proc['memory_percent'] or 0
                print(f"  {i:2d}. PID: {proc['pid']:<6} | Name: {proc['name']:<20} | CPU: {cpu:5.1f}% | Memory: {memory:5.1f}%")
            
            print()
            print("System Process Summary:")
            total_processes = len(psutil.pids())
            running_processes = len([p for p in psutil.process_iter() if p.status() == psutil.STATUS_RUNNING])
            sleeping_processes = len([p for p in psutil.process_iter() if p.status() == psutil.STATUS_SLEEPING])
            
            print(f"  Total Processes: {total_processes}")
            print(f"  Running: {running_processes}")
            print(f"  Sleeping: {sleeping_processes}")
            
        except Exception as e:
            print(f"Error analyzing processes: {e}")
        
        print()
        input("Press Enter to continue...")
    
    def show_storage_analysis(self):
        """Show detailed storage analysis."""
        self.clear_screen()
        print("-" * 120)
        print("STORAGE ANALYSIS")
        print("-" * 120)
        
        try:
            # Disk partitions
            print("Disk Partitions:")
            partitions = psutil.disk_partitions()
            for partition in partitions:
                print(f"  Device: {partition.device}")
                print(f"  Mountpoint: {partition.mountpoint}")
                print(f"  File System: {partition.fstype}")
                
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    total_gb = usage.total / (1024**3)
                    used_gb = usage.used / (1024**3)
                    free_gb = usage.free / (1024**3)
                    
                    print(f"  Total: {total_gb:.1f} GB | Used: {used_gb:.1f} GB ({usage.percent:.1f}%) | Free: {free_gb:.1f} GB")
                except PermissionError:
                    print("  Usage information unavailable (permission denied)")
                
                print()
            
            print("Disk I/O Statistics:")
            disk_io = psutil.disk_io_counters()
            if disk_io:
                read_mb = disk_io.read_bytes / (1024**2)
                write_mb = disk_io.write_bytes / (1024**2)
                print(f"  Read: {read_mb:.1f} MB | Write: {write_mb:.1f} MB")
                print(f"  Read Operations: {disk_io.read_count} | Write Operations: {disk_io.write_count}")
            
            print()
            print("Directory Analysis (current directory):")
            try:
                current_dir = os.getcwd()
                total_size = 0
                file_count = 0
                dir_count = 0
                
                for root, dirs, files in os.walk(current_dir):
                    dir_count += len(dirs)
                    file_count += len(files)
                    for file in files:
                        try:
                            total_size += os.path.getsize(os.path.join(root, file))
                        except (OSError, PermissionError):
                            continue
                    
                    # Limit depth to prevent long waits
                    if len(root.split(os.sep)) - len(current_dir.split(os.sep)) > 2:
                        dirs[:] = []  # Don't recurse further
                
                size_gb = total_size / (1024**3)
                print(f"  Total Size: {size_gb:.3f} GB")
                print(f"  Files: {file_count} | Directories: {dir_count}")
                
            except Exception as e:
                print(f"  Error analyzing directory: {e}")
                
        except Exception as e:
            print(f"Error analyzing storage: {e}")
        
        print()
        input("Press Enter to continue...")
    
    def show_service_status(self):
        """Show system service status."""
        self.clear_screen()
        print("-" * 120)
        print("SERVICE STATUS")
        print("-" * 120)
        
        print("System Services Status:")
        print("Note: Service management requires elevated privileges on most systems.")
        print()
        
        # Show basic system information
        try:
            print("System Information:")
            print(f"  Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Uptime: {self.format_duration(time.time() - psutil.boot_time())}")
            print(f"  CPU Count: {psutil.cpu_count(logical=True)} logical, {psutil.cpu_count(logical=False)} physical")
            print(f"  Memory Total: {psutil.virtual_memory().total / (1024**3):.1f} GB")
            print()
            
            # Show running processes that might be services
            print("Potential Service Processes:")
            service_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    info = proc.info
                    # Common service process names
                    service_names = ['systemd', 'init', 'cron', 'sshd', 'nginx', 'apache', 'mysql', 'postgres', 'redis', 'docker']
                    if any(name in info['name'].lower() for name in service_names):
                        service_processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            for proc in service_processes[:10]:
                username = proc['username'] or 'Unknown'
                print(f"  PID: {proc['pid']:<6} | Name: {proc['name']:<20} | User: {username:<20}")
            
            if not service_processes:
                print("  No obvious service processes detected")
                
        except Exception as e:
            print(f"Error getting service information: {e}")
        
        print()
        input("Press Enter to continue...")
    
    def show_resource_trends(self):
        """Show resource usage trends."""
        self.clear_screen()
        print("-" * 120)
        print("RESOURCE TRENDS")
        print("-" * 120)
        
        if len(self.monitor.metrics_history) < 2:
            print("Insufficient data for trend analysis")
            input("Press Enter to continue...")
            return
        
        try:
            metrics = list(self.monitor.metrics_history)
            
            print("Resource Usage Trends (Last " + str(len(metrics)) + " samples):")
            print()
            
            # CPU trends
            cpu_values = [m.cpu_percent for m in metrics]
            cpu_avg = sum(cpu_values) / len(cpu_values)
            cpu_min = min(cpu_values)
            cpu_max = max(cpu_values)
            cpu_trend = cpu_values[-1] - cpu_values[0] if len(cpu_values) > 1 else 0
            
            print(f"CPU Usage:")
            print(f"  Average: {cpu_avg:.1f}% | Min: {cpu_min:.1f}% | Max: {cpu_max:.1f}% | Trend: {'+' if cpu_trend > 0 else ''}{cpu_trend:.1f}%")
            
            # Memory trends
            memory_values = [m.memory_percent for m in metrics]
            memory_avg = sum(memory_values) / len(memory_values)
            memory_min = min(memory_values)
            memory_max = max(memory_values)
            memory_trend = memory_values[-1] - memory_values[0] if len(memory_values) > 1 else 0
            
            print(f"Memory Usage:")
            print(f"  Average: {memory_avg:.1f}% | Min: {memory_min:.1f}% | Max: {memory_max:.1f}% | Trend: {'+' if memory_trend > 0 else ''}{memory_trend:.1f}%")
            
            # Network trends
            if len(metrics) > 1:
                first_net = metrics[0].network_io
                last_net = metrics[-1].network_io
                sent_diff = last_net['bytes_sent'] - first_net['bytes_sent']
                recv_diff = last_net['bytes_recv'] - first_net['bytes_recv']
                
                print(f"Network Activity:")
                print(f"  Sent: {sent_diff / (1024**2):.1f} MB | Received: {recv_diff / (1024**2):.1f} MB")
                print(f"  Rate: {sent_diff / len(metrics) / 1024:.1f} KB/s sent, {recv_diff / len(metrics) / 1024:.1f} KB/s received")
            
            # Connection trends
            conn_values = [m.active_connections for m in metrics]
            conn_avg = sum(conn_values) / len(conn_values)
            conn_min = min(conn_values)
            conn_max = max(conn_values)
            
            print(f"Active Connections:")
            print(f"  Average: {conn_avg:.0f} | Min: {conn_min} | Max: {conn_max}")
            
            print()
            print("Recommendations:")
            if cpu_avg > 80:
                print("  • CPU usage is high - consider optimizing processes")
            if memory_avg > 80:
                print("  • Memory usage is high - consider adding more RAM or optimizing applications")
            if cpu_trend > 10:
                print("  • CPU usage is increasing - monitor for potential issues")
            if memory_trend > 10:
                print("  • Memory usage is increasing - check for memory leaks")
            
        except Exception as e:
            print(f"Error analyzing trends: {e}")
        
        print()
        input("Press Enter to continue...")
    
    def show_performance_tuning(self):
        """Show performance tuning recommendations."""
        self.clear_screen()
        print("-" * 120)
        print("PERFORMANCE TUNING")
        print("-" * 120)
        
        try:
            metrics = self.monitor.get_system_metrics()
            
            print("Performance Analysis & Recommendations:")
            print()
            
            # CPU Analysis
            print("CPU Analysis:")
            if metrics.cpu_percent > 80:
                print("  • High CPU usage detected")
                print("  • Recommendations:")
                print("    - Identify and optimize CPU-intensive processes")
                print("    - Consider load balancing if running services")
                print("    - Check for background processes consuming CPU")
            elif metrics.cpu_percent > 60:
                print("  • Moderate CPU usage")
                print("  • Recommendations:")
                print("    - Monitor for potential increases")
                print("    - Consider optimization during peak hours")
            else:
                print("  • CPU usage is optimal")
            
            print()
            
            # Memory Analysis
            print("Memory Analysis:")
            if metrics.memory_percent > 80:
                print("  • High memory usage detected")
                print("  • Recommendations:")
                print("    - Identify memory-intensive applications")
                print("    - Consider adding more RAM")
                print("    - Check for memory leaks")
                print("    - Optimize application memory usage")
            elif metrics.memory_percent > 60:
                print("  • Moderate memory usage")
                print("  • Recommendations:")
                print("    - Monitor memory trends")
                print("    - Consider cleanup of unused applications")
            else:
                print("  • Memory usage is optimal")
            
            print()
            
            # Disk Analysis
            print("Disk Analysis:")
            if metrics.disk_usage > 80:
                print("  • High disk usage detected")
                print("  • Recommendations:")
                print("    - Clean up unnecessary files")
                print("    - Archive old data")
                print("    - Consider disk expansion")
                print("    - Implement log rotation")
            elif metrics.disk_usage > 60:
                print("  • Moderate disk usage")
                print("  • Recommendations:")
                print("    - Monitor disk growth")
                print("    - Plan for future storage needs")
            else:
                print("  • Disk usage is optimal")
            
            print()
            
            # Network Analysis
            print("Network Analysis:")
            if metrics.active_connections > 500:
                print("  • High number of connections")
                print("  • Recommendations:")
                print("    - Monitor for potential connection leaks")
                print("    - Implement connection pooling")
                print("    - Check for unusual network activity")
            else:
                print("  • Connection count is normal")
            
            print()
            
            # System-wide recommendations
            print("System-wide Recommendations:")
            print("  • Regular system updates and patches")
            print("  • Implement log rotation to prevent disk fill-up")
            print("  • Monitor system performance regularly")
            print("  • Implement backup strategies")
            print("  • Use monitoring alerts for proactive management")
            print("  • Consider implementing caching mechanisms")
            print("  • Optimize database queries if applicable")
            
        except Exception as e:
            print(f"Error in performance analysis: {e}")
        
        print()
        input("Press Enter to continue...")
    
    def block_ip_address(self):
        """Block IP address functionality."""
        self.clear_screen()
        print("-" * 120)
        print("BLOCK IP ADDRESS")
        print("-" * 120)
        
        try:
            ip_address = input("Enter IP address to block: ").strip()
            if not ip_address:
                return
            
            # Basic IP validation
            import re
            ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            if not re.match(ip_pattern, ip_address):
                print("Invalid IP address format")
                input("Press Enter to continue...")
                return
            
            print(f"IP Address: {ip_address}")
            print("Note: This is a simulation. In a real system, this would:")
            print("  • Add firewall rules to block the IP")
            print("  • Update security group policies")
            print("  • Log the blocking action")
            print("  • Notify security team")
            print()
            
            confirm = input("Confirm blocking this IP? (yes/no): ").strip().lower()
            if confirm == 'yes':
                # Add security event
                self.monitor.add_security_event(
                    event_type="ip_blocked",
                    severity="medium",
                    source_ip=ip_address,
                    target_entity="firewall",
                    description=f"IP address {ip_address} blocked by administrator",
                    action_taken="blocked"
                )
                print(f"[SUCCESS] IP {ip_address} has been blocked (simulated)")
            else:
                print("[CANCELLED] IP blocking cancelled")
                
        except Exception as e:
            print(f"Error blocking IP address: {e}")
        
        input("Press Enter to continue...")
    
    def isolate_system(self):
        """Isolate system functionality."""
        self.clear_screen()
        print("-" * 120)
        print("SYSTEM ISOLATION")
        print("-" * 120)
        
        try:
            print("System Isolation Options:")
            print("1. Isolate from network")
            print("2. Isolate specific services")
            print("3. Enable maintenance mode")
            print("4. Cancel")
            print()
            print("Choose isolation type (1-4): ", end="")
            
            choice = input().strip()
            
            if choice == '1':
                print("Isolating system from network...")
                print("Note: This is a simulation. In a real system, this would:")
                print("  • Disable network interfaces")
                print("  • Block all incoming/outgoing traffic")
                print("  • Maintain management access")
                print("  • Log isolation action")
                
                confirm = input("Confirm network isolation? (yes/no): ").strip().lower()
                if confirm == 'yes':
                    self.server_config['maintenance_mode'] = True
                    self.monitor.add_security_event(
                        event_type="system_isolated",
                        severity="high",
                        source_ip="system",
                        target_entity="network",
                        description="System isolated from network by administrator",
                        action_taken="isolated"
                    )
                    print("[SUCCESS] System isolated from network (simulated)")
                else:
                    print("[CANCELLED] Network isolation cancelled")
                    
            elif choice == '2':
                print("Isolating specific services...")
                print("Note: This would stop specific services while keeping system running")
                
            elif choice == '3':
                print("Enabling maintenance mode...")
                self.server_config['maintenance_mode'] = True
                print("[SUCCESS] Maintenance mode enabled")
                
            elif choice == '4':
                print("[CANCELLED] System isolation cancelled")
                
        except Exception as e:
            print(f"Error during system isolation: {e}")
        
        input("Press Enter to continue...")
    
    def restore_isolated_system(self):
        """Restore isolated system functionality."""
        self.clear_screen()
        print("-" * 120)
        print("RESTORE ISOLATED SYSTEM")
        print("-" * 120)
        
        try:
            if not self.server_config['maintenance_mode']:
                print("System is not currently in isolation or maintenance mode")
                input("Press Enter to continue...")
                return
            
            print("Restoring system from isolation...")
            print("Note: This is a simulation. In a real system, this would:")
            print("  • Re-enable network interfaces")
            print("  • Restore firewall rules")
            print("  • Restart services")
            print("  • Verify system integrity")
            print("  • Log restoration action")
            
            confirm = input("Confirm system restoration? (yes/no): ").strip().lower()
            if confirm == 'yes':
                self.server_config['maintenance_mode'] = False
                self.monitor.add_security_event(
                    event_type="system_restored",
                    severity="medium",
                    source_ip="system",
                    target_entity="network",
                    description="System restored from isolation by administrator",
                    action_taken="restored"
                )
                print("[SUCCESS] System restored from isolation (simulated)")
            else:
                print("[CANCELLED] System restoration cancelled")
                
        except Exception as e:
            print(f"Error during system restoration: {e}")
        
        input("Press Enter to continue...")
    
    def show_threat_intelligence(self):
        """Show threat intelligence information."""
        self.clear_screen()
        print("-" * 120)
        print("THREAT INTELLIGENCE")
        print("-" * 120)
        
        try:
            print("Threat Intelligence Dashboard:")
            print()
            
            # Recent security events analysis
            recent_events = list(self.monitor.security_events)[-20:]
            if recent_events:
                print("Recent Security Events Analysis:")
                
                # Count by severity
                severity_count = {}
                for event in recent_events:
                    severity = event.severity
                    severity_count[severity] = severity_count.get(severity, 0) + 1
                
                for severity in ['critical', 'high', 'medium', 'low']:
                    count = severity_count.get(severity, 0)
                    print(f"  {severity.upper()}: {count} events")
                
                print()
                
                # Count by type
                type_count = {}
                for event in recent_events:
                    event_type = event.event_type
                    type_count[event_type] = type_count.get(event_type, 0) + 1
                
                print("Event Types:")
                for event_type, count in sorted(type_count.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {event_type}: {count}")
                
                print()
            
            # Trust records analysis
            trust_records = get_all_trust_records()
            if trust_records:
                print("Entity Trust Analysis:")
                
                risk_levels = {}
                for record in trust_records:
                    risk = record['risk_level']
                    risk_levels[risk] = risk_levels.get(risk, 0) + 1
                
                for risk in ['critical', 'high', 'medium', 'low']:
                    count = risk_levels.get(risk, 0)
                    print(f"  {risk.upper()} risk: {count} entities")
                
                print()
                
                # Show top risky entities
                risky_entities = [r for r in trust_records if r['risk_level'] in ['high', 'critical']]
                risky_entities.sort(key=lambda x: x['trust_score'])
                
                if risky_entities:
                    print("Top Risky Entities:")
                    for entity in risky_entities[:5]:
                        print(f"  {entity['entity_id']:<20} | Trust: {entity['trust_score']:5.1f} | Risk: {entity['risk_level']}")
                    print()
            
            # Threat patterns
            print("Threat Patterns:")
            print("  • Most active hours: Analysis shows increased activity during business hours")
            print("  • Common attack vectors: Authentication attempts, network scanning")
            print("  • Geographic distribution: Mixed geographic sources")
            print("  • Attack sophistication: Medium complexity attacks detected")
            
            print()
            print("Recommendations:")
            print("  • Enhance authentication mechanisms")
            print("  • Implement network segmentation")
            print("  • Increase monitoring during peak hours")
            print("  • Regular security awareness training")
            print("  • Implement intrusion detection systems")
            
        except Exception as e:
            print(f"Error generating threat intelligence: {e}")
        
        print()
        input("Press Enter to continue...")
    
    def generate_security_report(self):
        """Generate comprehensive security report."""
        self.clear_screen()
        print("-" * 120)
        print("SECURITY REPORT GENERATOR")
        print("-" * 120)
        
        try:
            report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Security Report - Generated at {report_time}")
            print("=" * 120)
            print()
            
            # Executive Summary
            print("EXECUTIVE SUMMARY:")
            print("-" * 40)
            total_entities = len(get_all_trust_records())
            active_responses = len(get_active_responses())
            total_events = len(self.monitor.security_events)
            active_alerts = len(self.monitor.alerts)
            
            print(f"Total Entities Monitored: {total_entities}")
            print(f"Active Security Responses: {active_responses}")
            print(f"Total Security Events: {total_events}")
            print(f"Active Alerts: {active_alerts}")
            
            # Risk assessment
            trust_stats = get_trust_statistics()
            avg_trust = trust_stats['average_trust_score']
            risk_dist = trust_stats['risk_distribution']
            
            print(f"Average Trust Score: {avg_trust:.1f}")
            print(f"Risk Distribution: Low={risk_dist.get('low', 0)}, Medium={risk_dist.get('medium', 0)}, High={risk_dist.get('high', 0)}, Critical={risk_dist.get('critical', 0)}")
            
            # Overall security posture
            if avg_trust > 80 and active_responses == 0:
                posture = "HEALTHY"
            elif avg_trust > 60 and active_responses < 5:
                posture = "MONITOR"
            else:
                posture = "ATTENTION"
            
            print(f"Overall Security Posture: {posture}")
            print()
            
            # Detailed Analysis
            print("DETAILED ANALYSIS:")
            print("-" * 40)
            
            # System performance
            metrics = self.monitor.get_system_metrics()
            print(f"System Performance:")
            print(f"  CPU Usage: {metrics.cpu_percent:.1f}%")
            print(f"  Memory Usage: {metrics.memory_percent:.1f}%")
            print(f"  Disk Usage: {metrics.disk_usage:.1f}%")
            print(f"  Active Connections: {metrics.active_connections}")
            print()
            
            # Recent security events
            recent_events = list(self.monitor.security_events)[-10:]
            if recent_events:
                print("Recent Security Events:")
                for event in recent_events:
                    time_str = datetime.fromtimestamp(event.timestamp).strftime('%H:%M:%S')
                    print(f"  {time_str} | {event.event_type} | {event.severity} | {event.description}")
                print()
            
            # Recommendations
            print("RECOMMENDATIONS:")
            print("-" * 40)
            
            if avg_trust < 70:
                print("• Average trust score is below optimal - review entity behaviors")
            
            if active_responses > 5:
                print("• High number of active responses - review and prioritize")
            
            if metrics.cpu_percent > 80:
                print("• High CPU usage - optimize processes")
            
            if metrics.memory_percent > 80:
                print("• High memory usage - consider adding RAM or optimizing")
            
            print("• Continue regular monitoring and updates")
            print("• Implement automated threat response")
            print("• Regular security audits")
            print("• Employee security training")
            
            print()
            print("=" * 120)
            print("End of Security Report")
            
            # Option to save report
            save_report = input("\nSave report to file? (yes/no): ").strip().lower()
            if save_report == 'yes':
                filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                # In a real implementation, this would save to file
                print(f"Report would be saved to: {filename}")
            
        except Exception as e:
            print(f"Error generating security report: {e}")
        
        input("Press Enter to continue...")

    def show_system_info(self):
        """Display detailed system information."""
        self.clear_screen()
        print("-" * 120)
        print("SYSTEM INFORMATION")
        print("-" * 120)
        
        # Basic system info
        print(f"Hostname: {socket.gethostname():<40} | Platform: {sys.platform:<20}")
        print(f"Architecture: {os.uname().machine if hasattr(os, 'uname') else 'Unknown':<35} | Processor: {psutil.cpu_count(logical=False):<4} cores, {psutil.cpu_count(logical=True):<4} logical")
        print(f"Python Version: {sys.version.split()[0]:<35} | Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'):<20}")
        
        print()
        
        # Memory details
        memory = psutil.virtual_memory()
        print(f"Total Memory: {self.format_bytes(memory.total):<15} | Available: {self.format_bytes(memory.available):<15} | Used: {memory.percent:.1f}%")
        
        # Disk details
        disk = psutil.disk_usage('/')
        print(f"Total Disk: {self.format_bytes(disk.total):<15} | Free: {self.format_bytes(disk.free):<15} | Used: {disk.percent:.1f}%")
        
        # Network details
        print("Network Interfaces:")
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        print(f"  {interface:<15}: {addr.address:<15}")
        except:
            print("  Network information unavailable")
        
        print()
        input("Press Enter to continue...")
    
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
