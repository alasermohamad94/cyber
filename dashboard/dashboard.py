"""
Cyber Defense System Dashboard

A simple command-line dashboard for monitoring the cyber defense system.
Provides real-time visualization of system status, threats, and responses.
"""

import time
import os
from typing import Dict, Any, List
from datetime import datetime

# Import system modules
from trust_system.trust_manager import get_trust_statistics, get_all_trust_records
from response.engine import get_active_responses, get_response_history


class CyberDefenseDashboard:
    """
    Command-line dashboard for the cyber defense system.
    """
    
    def __init__(self):
        self.running = True
        self.refresh_interval = 5  # seconds
        
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def format_timestamp(self, timestamp: float) -> str:
        """Format timestamp for display."""
        return datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
    
    def draw_header(self):
        """Draw dashboard header."""
        print("=" * 80)
        print("🛡️  CYBER DEFENSE SYSTEM DASHBOARD")
        print("=" * 80)
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    def draw_system_overview(self):
        """Draw system overview section."""
        stats = get_trust_statistics()
        
        print("📊 SYSTEM OVERVIEW")
        print("-" * 40)
        print(f"Total Entities: {stats['total_entities']}")
        print(f"Average Trust Score: {stats['average_trust_score']:.1f}")
        print(f"Active Responses: {len(get_active_responses())}")
        
        if stats['total_entities'] > 0:
            print(f"Trust Range: {stats['min_trust_score']:.1f} - {stats['max_trust_score']:.1f}")
        
        print()
    
    def draw_risk_distribution(self):
        """Draw risk distribution chart."""
        stats = get_trust_statistics()
        risk_dist = stats['risk_distribution']
        
        print("🚨 RISK DISTRIBUTION")
        print("-" * 40)
        
        total = sum(risk_dist.values()) if risk_dist.values() else 1
        
        for level in ['low', 'medium', 'high', 'critical']:
            count = risk_dist.get(level, 0)
            percentage = (count / total) * 100 if total > 0 else 0
            
            # Choose emoji based on risk level
            emoji = {'low': '🟢', 'medium': '🟡', 'high': '🟠', 'critical': '🔴'}[level]
            
            # Create bar
            bar_length = int(percentage / 2)
            bar = '█' * bar_length + '░' * (50 - bar_length)
            
            print(f"{emoji} {level.upper():10} {count:3d} ({percentage:5.1f}%) {bar}")
        
        print()
    
    def draw_active_responses(self):
        """Draw active responses section."""
        active = get_active_responses()
        
        print("🚨 ACTIVE RESPONSES")
        print("-" * 40)
        
        if not active:
            print("✅ No active responses")
        else:
            for response in active[:5]:  # Show max 5
                entity_id = response['entity_id']
                action_type = response['action_type']
                timestamp = response['timestamp']
                
                emoji = {'monitor': '👁️', 'alert': '⚠️', 'block': '🚫', 'isolate': '🔒'}.get(action_type, '❓')
                
                print(f"{emoji} {entity_id[:20]:20} {action_type:8} {self.format_timestamp(timestamp)}")
            
            if len(active) > 5:
                print(f"... and {len(active) - 5} more")
        
        print()
    
    def draw_recent_activity(self):
        """Draw recent activity section."""
        history = get_response_history(10)
        
        print("📋 RECENT ACTIVITY")
        print("-" * 40)
        
        if not history:
            print("No recent activity")
        else:
            for response in history[-5:]:  # Show last 5
                entity_id = response['entity_id']
                action_type = response['action_type']
                status = response['status']
                timestamp = response['timestamp']
                
                status_emoji = {'completed': '✅', 'failed': '❌', 'cancelled': '⏹️'}.get(status, '❓')
                action_emoji = {'monitor': '👁️', 'alert': '⚠️', 'block': '🚫', 'isolate': '🔒'}.get(action_type, '❓')
                
                print(f"{status_emoji} {action_emoji} {entity_id[:15]:15} {action_type:8} {self.format_timestamp(timestamp)}")
        
        print()
    
    def draw_high_risk_entities(self):
        """Draw high-risk entities section."""
        records = get_all_trust_records()
        
        # Filter high and critical risk entities
        high_risk = [r for r in records if r['risk_level'] in ['high', 'critical']]
        high_risk.sort(key=lambda x: x['trust_score'])
        
        print("⚠️  HIGH-RISK ENTITIES")
        print("-" * 40)
        
        if not high_risk:
            print("✅ No high-risk entities detected")
        else:
            for record in high_risk[:5]:  # Show top 5
                entity_id = record['entity_id']
                trust_score = record['trust_score']
                risk_level = record['risk_level']
                trend = record['trust_trend']
                
                risk_emoji = {'high': '🟠', 'critical': '🔴'}[risk_level]
                trend_emoji = {'improving': '📈', 'declining': '📉', 'stable': '➡️'}.get(trend, '❓')
                
                print(f"{risk_emoji} {entity_id[:20]:20} {trust_score:5.1f} {trend_emoji} {risk_level}")
            
            if len(high_risk) > 5:
                print(f"... and {len(high_risk) - 5} more")
        
        print()
    
    def draw_footer(self):
        """Draw dashboard footer."""
        print("=" * 80)
        print("Press Ctrl+C to exit | Auto-refresh every 5 seconds")
        print("=" * 80)
    
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
        """Run the dashboard."""
        try:
            while self.running:
                self.draw_dashboard()
                time.sleep(self.refresh_interval)
        except KeyboardInterrupt:
            print("\n\n👋 Dashboard stopped. Goodbye!")
            self.running = False


def main():
    """Main entry point for the dashboard."""
    print("🚀 Starting Cyber Defense System Dashboard...")
    print("Initializing dashboard components...")
    
    dashboard = CyberDefenseDashboard()
    
    print("Dashboard ready! Press Ctrl+C to stop.")
    time.sleep(2)
    
    dashboard.run()


if __name__ == "__main__":
    main()