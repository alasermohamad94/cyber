"""
Interactive Cyber Defense System Dashboard

A controllable dashboard for monitoring and managing the cyber defense system.
Provides interactive controls for real-time monitoring and manual intervention.
"""

import sys
import os
import time
import threading
from typing import Dict, Any, List
from datetime import datetime

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import system modules
from trust_system import get_trust_statistics, get_all_trust_records, reset_trust_score
from response import get_active_responses, get_response_history, cancel_response
from main import CyberDefenseSystem
try:
    from .color_theme import ColorTheme, ColorUtils
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from color_theme import ColorTheme, ColorUtils


class InteractiveDashboard:
    """
    Interactive command-line dashboard with control capabilities.
    """
    
    def __init__(self):
        self.running = True
        self.refresh_interval = 3  # seconds
        self.auto_refresh = True
        self.cds = CyberDefenseSystem()
        self.last_command = ""
        self.theme = ColorTheme()
        self.color_utils = ColorUtils()
        
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def format_timestamp(self, timestamp: float) -> str:
        """Format timestamp for display."""
        return datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
    
    def draw_header(self):
        """Draw dashboard header."""
        header_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        reset = self.theme.Terminal.RESET
        
        print(f"{separator_color}{'=' * 80}{reset}")
        print(f"{header_color}INTERACTIVE CYBER DEFENSE SYSTEM DASHBOARD{reset}")
        print(f"{separator_color}{'=' * 80}{reset}")
        print(f"{text_color}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{reset}")
        print(f"{text_color}Auto-refresh: {'ON' if self.auto_refresh else 'OFF'} | Interval: {self.refresh_interval}s{reset}")
        print()
    
    def draw_system_overview(self):
        """Draw system overview section."""
        stats = get_trust_statistics()
        
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        reset = self.theme.Terminal.RESET
        
        print(f"{title_color}SYSTEM OVERVIEW{reset}")
        print(f"{separator_color}{'-' * 40}{reset}")
        print(f"{text_color}Total Entities: {stats['total_entities']}{reset}")
        
        avg_score = stats['average_trust_score']
        score_color = self.color_utils.get_terminal_color_for_value(avg_score, 100, "status")
        print(f"{text_color}Average Trust Score: {score_color}{avg_score:.1f}{reset}")
        print(f"{text_color}Active Responses: {success_color}{len(get_active_responses())}{reset}")
        
        if stats['total_entities'] > 0:
            print(f"{text_color}Trust Range: {stats['min_trust_score']:.1f} - {stats['max_trust_score']:.1f}{reset}")
        
        print()
    
    def draw_risk_distribution(self):
        """Draw risk distribution chart."""
        stats = get_trust_statistics()
        risk_dist = stats['risk_distribution']
        
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        reset = self.theme.Terminal.RESET
        
        print(f"{title_color}RISK DISTRIBUTION{reset}")
        print(f"{separator_color}{'-' * 40}{reset}")
        
        total = sum(risk_dist.values()) if risk_dist.values() else 1
        
        # Color mapping for risk levels
        risk_colors = {
            'low': self.theme.Terminal.SUCCESS,
            'medium': self.theme.Terminal.WARNING,
            'high': self.theme.Terminal.ERROR,
            'critical': self.theme.Terminal.CRITICAL
        }
        
        for level in ['low', 'medium', 'high', 'critical']:
            count = risk_dist.get(level, 0)
            percentage = (count / total) * 100 if total > 0 else 0
            
            # Create bar with forest theme
            bar_length = int(percentage / 2)
            bar_color = risk_colors.get(level, self.theme.Terminal.PRIMARY)
            bar = f"{bar_color}{'█' * bar_length}{self.theme.Terminal.DIM}{'.' * (50 - bar_length)}{reset}"
            
            print(f"{level.upper():10} {text_color}{count:3d} ({percentage:5.1f}%) {bar}{reset}")
        
        print()
    
    def draw_active_responses(self):
        """Draw active responses section with controls."""
        active = get_active_responses()
        
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        warning_color = self.theme.Terminal.WARNING
        reset = self.theme.Terminal.RESET
        
        print(f"{title_color}ACTIVE RESPONSES{reset}")
        print(f"{separator_color}{'-' * 40}{reset}")
        
        if not active:
            print(f"{text_color}No active responses{reset}")
        else:
            for i, response in enumerate(active[:5], 1):
                entity_id = response['entity_id']
                action_type = response['action_type']
                timestamp = response['timestamp']
                action_id = response.get('action_id', 'N/A')
                
                # Color code action types
                action_color = success_color if action_type in ['monitor', 'alert'] else warning_color
                
                print(f"{text_color}{i}. {entity_id[:20]:20} {action_color}{action_type:8}{reset} {text_color}{self.format_timestamp(timestamp)}{reset}")
                print(f"{text_color}   Action ID: {action_id}{reset}")
            
            if len(active) > 5:
                print(f"{text_color}... and {len(active) - 5} more{reset}")
        
        print()
    
    def draw_recent_activity(self):
        """Draw recent activity section."""
        history = get_response_history(10)
        
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        error_color = self.theme.Terminal.ERROR
        reset = self.theme.Terminal.RESET
        
        print(f"{title_color}RECENT ACTIVITY{reset}")
        print(f"{separator_color}{'-' * 40}{reset}")
        
        if not history:
            print(f"{text_color}No recent activity{reset}")
        else:
            for response in history[-5:]:
                entity_id = response['entity_id']
                action_type = response['action_type']
                status = response['status']
                timestamp = response['timestamp']
                
                # Color code status
                if status == 'completed':
                    status_color = success_color
                elif status == 'failed':
                    status_color = error_color
                else:
                    status_color = self.theme.Terminal.WARNING
                
                print(f"{text_color}{entity_id[:15]:15} {action_type:8} {status_color}{status:10}{reset} {text_color}{self.format_timestamp(timestamp)}{reset}")
        
        print()
    
    def draw_high_risk_entities(self):
        """Draw high-risk entities section with controls."""
        records = get_all_trust_records()
        
        # Filter high and critical risk entities
        high_risk = [r for r in records if r['risk_level'] in ['high', 'critical']]
        high_risk.sort(key=lambda x: x['trust_score'])
        
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        warning_color = self.theme.Terminal.WARNING
        critical_color = self.theme.Terminal.CRITICAL
        reset = self.theme.Terminal.RESET
        
        print(f"{title_color}HIGH-RISK ENTITIES{reset}")
        print(f"{separator_color}{'-' * 40}{reset}")
        
        if not high_risk:
            print(f"{text_color}No high-risk entities detected{reset}")
        else:
            for i, record in enumerate(high_risk[:5], 1):
                entity_id = record['entity_id']
                trust_score = record['trust_score']
                risk_level = record['risk_level']
                trend = record['trust_trend']
                
                # Color code risk level
                if risk_level == 'critical':
                    risk_color = critical_color
                elif risk_level == 'high':
                    risk_color = warning_color
                else:
                    risk_color = text_color
                
                print(f"{text_color}{i}. {entity_id[:20]:20} {trust_score:5.1f} {trend:10} {risk_color}{risk_level}{reset}")
            
            if len(high_risk) > 5:
                print(f"{text_color}... and {len(high_risk) - 5} more{reset}")
        
        print()
    
    def draw_controls(self):
        """Draw control menu."""
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        warning_color = self.theme.Terminal.WARNING
        reset = self.theme.Terminal.RESET
        
        print(f"{title_color}CONTROLS{reset}")
        print(f"{separator_color}{'-' * 40}{reset}")
        print(f"{text_color}1. {success_color}Analyze new entity{reset}")
        print(f"{text_color}2. {warning_color}Cancel active response{reset}")
        print(f"{text_color}3. {warning_color}Reset entity trust score{reset}")
        print(f"{text_color}4. Toggle auto-refresh{reset}")
        print(f"{text_color}5. Set refresh interval{reset}")
        print(f"{text_color}6. Show detailed entity info{reset}")
        print(f"{text_color}7. {success_color}Run quick demo{reset}")
        print(f"{text_color}8. {warning_color}Exit{reset}")
        print()
        print(f"{text_color}Enter command number (or 'q' to quit): {reset}", end="")
    
    def analyze_new_entity(self):
        """Analyze a new entity interactively."""
        self.clear_screen()
        
        header_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        reset = self.theme.Terminal.RESET
        
        print(f"{header_color}ANALYZE NEW ENTITY{reset}")
        print(f"{separator_color}{'=' * 50}{reset}")
        
        try:
            entity_id = input(f"{text_color}Entity ID: {reset}").strip()
            if not entity_id:
                return
            
            print("\nEnter entity data (format: key=value, separated by commas):")
            print("Example: connection_rate=0.8, failed_auth_count=10, total_auth_count=20")
            
            data_input = input("Data: ").strip()
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
            
            # Analyze entity
            result = self.cds.analyze_entity(entity_id, entity_data)
            
            print(f"\nAnalysis complete for {entity_id}")
            print(f"Behavior Score: {result['behavior_profile']['behavior_score']:.1f}")
            print(f"Decision: {result['decision']['action']}")
            if result['response']:
                print(f"Response Status: {result['response']['status']}")
            
            input("\nPress Enter to continue...")
            
        except Exception as e:
            print(f"Error: {e}")
            input("Press Enter to continue...")
    
    def cancel_response_action(self):
        """Cancel an active response."""
        active = get_active_responses()
        if not active:
            print("No active responses to cancel.")
            input("Press Enter to continue...")
            return
        
        self.clear_screen()
        print("CANCEL ACTIVE RESPONSE")
        print("=" * 50)
        
        print("Active responses:")
        for i, response in enumerate(active, 1):
            entity_id = response['entity_id']
            action_type = response['action_type']
            action_id = response.get('action_id', 'N/A')
            print(f"{i}. {entity_id} - {action_type} (ID: {action_id})")
        
        try:
            choice = input(f"\nEnter response number to cancel (1-{len(active)}): ").strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(active):
                    action_id = active[idx].get('action_id')
                    if action_id:
                        result = cancel_response(action_id)
                        print(f"Response {action_id} cancelled: {result['status']}")
                    else:
                        print("No action ID available for this response")
                else:
                    print("Invalid selection")
            else:
                print("Invalid input")
        except Exception as e:
            print(f"Error: {e}")
        
        input("Press Enter to continue...")
    
    def reset_trust_action(self):
        """Reset trust score for an entity."""
        records = get_all_trust_records()
        if not records:
            print("No entities found.")
            input("Press Enter to continue...")
            return
        
        self.clear_screen()
        print("RESET ENTITY TRUST SCORE")
        print("=" * 50)
        
        print("Available entities:")
        for i, record in enumerate(records, 1):
            entity_id = record['entity_id']
            trust_score = record['trust_score']
            risk_level = record['risk_level']
            print(f"{i}. {entity_id} - Trust: {trust_score:.1f} ({risk_level})")
        
        try:
            choice = input(f"\nEnter entity number to reset (1-{len(records)}): ").strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(records):
                    entity_id = records[idx]['entity_id']
                    new_score = input("Enter new trust score (0-100, default=100): ").strip()
                    
                    if new_score:
                        try:
                            new_score = float(new_score)
                            new_score = max(0.0, min(100.0, new_score))
                        except ValueError:
                            print("Invalid score, using 100")
                            new_score = 100.0
                    else:
                        new_score = 100.0
                    
                    success = reset_trust_score(entity_id, new_score)
                    if success:
                        print(f"Trust score for {entity_id} reset to {new_score:.1f}")
                    else:
                        print(f"Failed to reset trust score for {entity_id}")
                else:
                    print("Invalid selection")
            else:
                print("Invalid input")
        except Exception as e:
            print(f"Error: {e}")
        
        input("Press Enter to continue...")
    
    def toggle_auto_refresh(self):
        """Toggle auto-refresh on/off."""
        self.auto_refresh = not self.auto_refresh
        status = "ON" if self.auto_refresh else "OFF"
        print(f"Auto-refresh toggled {status}")
        time.sleep(1)
    
    def set_refresh_interval(self):
        """Set refresh interval."""
        try:
            interval = input("Enter refresh interval in seconds (1-30): ").strip()
            if interval.isdigit():
                interval = int(interval)
                if 1 <= interval <= 30:
                    self.refresh_interval = interval
                    print(f"Refresh interval set to {interval} seconds")
                else:
                    print("Interval must be between 1 and 30 seconds")
            else:
                print("Invalid input")
        except Exception as e:
            print(f"Error: {e}")
        
        time.sleep(1)
    
    def show_entity_details(self):
        """Show detailed information about an entity."""
        records = get_all_trust_records()
        if not records:
            print("No entities found.")
            input("Press Enter to continue...")
            return
        
        self.clear_screen()
        print("ENTITY DETAILS")
        print("=" * 50)
        
        print("Available entities:")
        for i, record in enumerate(records, 1):
            entity_id = record['entity_id']
            trust_score = record['trust_score']
            risk_level = record['risk_level']
            print(f"{i}. {entity_id} - Trust: {trust_score:.1f} ({risk_level})")
        
        try:
            choice = input(f"\nEnter entity number (1-{len(records)}): ").strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(records):
                    record = records[idx]
                    
                    self.clear_screen()
                    print(f"DETAILED INFORMATION: {record['entity_id']}")
                    print("=" * 60)
                    print(f"Trust Score: {record['trust_score']:.1f}")
                    print(f"Risk Level: {record['risk_level']}")
                    print(f"Trust Trend: {record['trust_trend']}")
                    print(f"Last Updated: {datetime.fromtimestamp(record['last_updated']).strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    if record['behavior_history']:
                        print(f"\nBehavior History (last {len(record['behavior_history'])} scores):")
                        for i, score in enumerate(record['behavior_history'][-10:], 1):
                            print(f"  {i}. {score:.1f}")
                    
                else:
                    print("Invalid selection")
            else:
                print("Invalid input")
        except Exception as e:
            print(f"Error: {e}")
        
        input("Press Enter to continue...")
    
    def run_quick_demo(self):
        """Run a quick demonstration."""
        self.clear_screen()
        print("RUNNING QUICK DEMO")
        print("=" * 50)
        
        # Create test entities
        test_entities = [
            {
                'entity_id': f'demo_entity_{int(time.time())}',
                'data': {
                    'connection_rate': 0.9,
                    'request_rate': 0.8,
                    'failed_auth_count': 12,
                    'total_auth_count': 15,
                    'unique_ports': 0.7,
                    'sensitive_access_count': 0.5,
                }
            }
        ]
        
        for entity in test_entities:
            result = self.cds.analyze_entity(entity['entity_id'], entity['data'])
            print(f"\nDemo analysis completed for {entity['entity_id']}")
            print(f"Behavior Score: {result['behavior_profile']['behavior_score']:.1f}")
            print(f"Decision: {result['decision']['action']}")
        
        input("\nPress Enter to continue...")
    
    def handle_command(self, command):
        """Handle user command."""
        if command == '1':
            self.analyze_new_entity()
        elif command == '2':
            self.cancel_response_action()
        elif command == '3':
            self.reset_trust_action()
        elif command == '4':
            self.toggle_auto_refresh()
        elif command == '5':
            self.set_refresh_interval()
        elif command == '6':
            self.show_entity_details()
        elif command == '7':
            self.run_quick_demo()
        elif command in ['8', 'q', 'quit', 'exit']:
            self.running = False
        else:
            print("Invalid command")
            time.sleep(1)
    
    def draw_dashboard(self):
        """Draw complete dashboard."""
        self.clear_screen()
        self.draw_header()
        self.draw_system_overview()
        self.draw_risk_distribution()
        self.draw_active_responses()
        self.draw_recent_activity()
        self.draw_high_risk_entities()
        self.draw_controls()
    
    def run_interactive(self):
        """Run interactive dashboard."""
        print("Starting Interactive Cyber Defense Dashboard...")
        time.sleep(2)
        
        while self.running:
            self.draw_dashboard()
            
            if self.auto_refresh:
                # Non-blocking input with timeout
                import select
                import sys
                
                print("Waiting for command (auto-refresh in 3 seconds)...")
                time.sleep(self.refresh_interval)
            else:
                command = input().strip().lower()
                self.handle_command(command)
    
    def run(self):
        """Run the dashboard."""
        try:
            self.run_interactive()
        except KeyboardInterrupt:
            print("\n\nDashboard stopped. Goodbye!")
            self.running = False


def main():
    """Main entry point for interactive dashboard."""
    dashboard = InteractiveDashboard()
    dashboard.run()


if __name__ == "__main__":
    main()
