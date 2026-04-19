"""
Cyber Defense System Dashboard

A simple command-line dashboard for monitoring cyber defense system.
Provides real-time visualization of system status, threats, and responses.
"""

import sys
import os
import time
from typing import Dict, Any, List
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import system modules
from trust_system import get_trust_statistics, get_all_trust_records
from response import get_active_responses, get_response_history
try:
    from .color_theme import ColorTheme, ColorUtils
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from color_theme import ColorTheme, ColorUtils


class CyberDefenseDashboard:
    """
    Command-line dashboard for the cyber defense system.
    """
    
    def __init__(self):
        self.running = True
        self.refresh_interval = 5  # seconds
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
        print(f"{header_color}CYBER DEFENSE SYSTEM DASHBOARD{reset}")
        print(f"{separator_color}{'=' * 80}{reset}")
        print(f"{text_color}Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{reset}")
        print()
    
    def draw_system_overview(self):
        """Draw system overview section."""
        stats = get_trust_statistics()
        
        title_color = self.theme.Terminal.PRIMARY_BOLD
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        success_color = self.theme.Terminal.SUCCESS
        warning_color = self.theme.Terminal.WARNING
        reset = self.theme.Terminal.RESET
        
        print(f"{title_color}SYSTEM OVERVIEW{reset}")
        print(f"{separator_color}{'-' * 40}{reset}")
        print(f"{text_color}Total Entities: {stats['total_entities']}{reset}")
        
        # Color code average trust score
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
        """Draw active responses section."""
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
            for response in active[:5]:  # Show max 5
                entity_id = response['entity_id']
                action_type = response['action_type']
                timestamp = response['timestamp']
                
                # Color code action types
                action_color = success_color if action_type in ['monitor', 'alert'] else warning_color
                
                print(f"{text_color}{entity_id[:20]:20} {action_color}{action_type:8}{reset} {text_color}{self.format_timestamp(timestamp)}{reset}")
            
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
            for response in history[-5:]:  # Show last 5
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
                    status_color = warning_color = self.theme.Terminal.WARNING
                
                print(f"{text_color}{entity_id[:15]:15} {action_type:8} {status_color}{status:10}{reset} {text_color}{self.format_timestamp(timestamp)}{reset}")
        
        print()
    
    def draw_high_risk_entities(self):
        """Draw high-risk entities section."""
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
            for record in high_risk[:5]:  # Show top 5
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
                
                print(f"{text_color}{entity_id[:20]:20} {trust_score:5.1f} {trend:10} {risk_color}{risk_level}{reset}")
            
            if len(high_risk) > 5:
                print(f"{text_color}... and {len(high_risk) - 5} more{reset}")
        
        print()
    
    def draw_footer(self):
        """Draw dashboard footer."""
        separator_color = self.theme.Terminal.SECONDARY
        text_color = self.theme.Terminal.LIGHT
        reset = self.theme.Terminal.RESET
        
        print(f"{separator_color}{'=' * 80}{reset}")
        print(f"{text_color}Press Ctrl+C to exit | Auto-refresh every 5 seconds{reset}")
        print(f"{separator_color}{'=' * 80}{reset}")
    
    def draw_dashboard(self):
        """Draw complete dashboard."""
        self.clear_screen()
        self.draw_header()
        self.draw_system_overview()
        self.draw_risk_distribution()
        self.draw_active_responses()
        self.draw_recent_activity()
        self.draw_high_risk_entities()
        self.draw_footer()
    
    def run(self):
        """Run dashboard."""
        try:
            while self.running:
                self.draw_dashboard()
                time.sleep(self.refresh_interval)
        except KeyboardInterrupt:
            print("\n\nDashboard stopped. Goodbye!")
            self.running = False


def main():
    """Main entry point for the dashboard."""
    print("Starting Cyber Defense System Dashboard...")
    print("Initializing dashboard components...")
    
    dashboard = CyberDefenseDashboard()
    
    print("Dashboard ready! Press Ctrl+C to stop.")
    time.sleep(2)
    
    dashboard.run()


if __name__ == "__main__":
    main()
