#!/usr/bin/env python3
"""
Cyber Defense System - Main Entry Point

This is the main application that demonstrates the complete cyber defense system.
It integrates all modules: perception, prediction, decision engine, response, and trust system.
"""

import sys
import time
from typing import Dict, Any, List
from dataclasses import asdict

# Import the working modules
from perception.behavior_analysis import analyze_behavior, BehaviorProfile
from prediction.attack_prediction import predict_attack, AttackPrediction
from correlation.threat_correlation import ThreatCorrelationEngine

# Import empty modules (we'll implement basic functionality)
from decision_engine.descision_engine import make_decision
from prediction.model_inference import build_feature_vector, shadow_predict
from response.engine import execute_response
from trust_system.trust_manager import get_trust_record, update_trust_score


class CyberDefenseSystem:
    """
    Main cyber defense system that coordinates all modules.
    """
    
    def __init__(self):
        self.entity_trust_scores: Dict[str, float] = {}
        self.active_responses: List[Dict[str, Any]] = []
        self.correlation_engine = ThreatCorrelationEngine()
        
    def analyze_entity(self, entity_id: str, entity_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Complete analysis pipeline for a single entity.
        
        Args:
            entity_id: Unique identifier for the entity
            entity_data: Raw telemetry data about the entity
            
        Returns:
            Complete analysis results including behavior profile, prediction, decision, and response
        """
        print(f"\n[Analyzing] entity: {entity_id}")
        print(f"[Input] data: {entity_data}")
        
        # Step 1: Perception Layer - Analyze behavior
        print("[Perception] Analyzing behavior...")
        behavior_profile = analyze_behavior(entity_data)
        print(f"   Behavior Score: {behavior_profile.behavior_score:.1f}")
        print(f"   Anomaly Level: {behavior_profile.anomaly_level}")
        
        # Step 2: Prediction Layer - Predict attack stage
        print("[Prediction] Predicting attack stage...")
        attack_prediction = predict_attack(behavior_profile)
        print(f"   Current Stage: {attack_prediction.current_stage}")
        print(f"   Next Stage: {attack_prediction.next_stage}")
        print(f"   Confidence: {attack_prediction.confidence:.2f}")

        # Step 2b: ML shadow inference (advisory; does not replace rules)
        ml_advisory = shadow_predict({
            "entity_data": entity_data,
            "behavior_score": behavior_profile.behavior_score,
            "feature_vector": build_feature_vector(entity_data, behavior_profile.behavior_score),
        })
        if ml_advisory.get("enabled"):
            print(f"[ML Shadow] {ml_advisory.get('anomaly_label')} "
                  f"advisory={ml_advisory.get('advisory_score'):.1f}")

        # Step 2c: Threat correlation - link related events into one incident.
        correlation = self.correlation_engine.analyze(
            entity_id,
            entity_data,
            behavior_profile,
        )
        if correlation.correlated:
            print("[Correlation] Multi-stage incident linked automatically")
            print(f"   Incident Type: {correlation.incident_type}")
            print(f"   Source IP: {correlation.source_ip}")
        else:
            print("[Correlation] No related incident found in active window")
        
        # Step 3: Trust System - Update trust score
        print("[Trust System] Updating trust score...")
        current_trust = self.entity_trust_scores.get(entity_id, 100.0)
        new_trust = update_trust_score(
            entity_id,
            behavior_profile.behavior_score,
            current_trust,
            entity_data,
        )
        self.entity_trust_scores[entity_id] = new_trust
        trust_record = get_trust_record(entity_id) or {}
        print(f"   Trust Score: {new_trust:.1f}")
        print(f"   Risk Score: {trust_record.get('risk_score', 0.0):.1f}")
        print(f"   Asset Type: {trust_record.get('asset_type', 'employee_device')}")
        print(f"   Asset Criticality: {trust_record.get('asset_criticality', 1.0):.1f}")
        print(f"   Incident Type: {trust_record.get('last_incident_type', 'behavior_anomaly')}")
        print(f"   Incident Severity: {trust_record.get('last_incident_severity', 'low')}")
        
        # Step 4: Decision Engine - Make security decision
        print("[Decision Engine] Making security decision...")
        decision = make_decision(
            behavior_profile,
            attack_prediction,
            new_trust,
            ml_advisory,
            correlation=asdict(correlation),
            risk_score=trust_record.get('risk_score', 0.0),
            risk_level=trust_record.get('risk_level', 'low'),
        )
        print(f"   Decision: {decision['action']}")
        print(f"   Severity: {decision['severity']}")
        
        # Step 5: Response Engine - Execute response if needed
        response_result = None
        if decision['action'] != 'monitor':
            print("[Response Engine] Executing response...")
            response_result = execute_response(entity_id, decision)
            print(f"   Response: {response_result['status']}")
            self.active_responses.append({
                'entity_id': entity_id,
                'timestamp': time.time(),
                'decision': decision,
                'response': response_result
            })
        else:
            print("[Response Engine] No action needed - continuing to monitor")
        
        # Compile complete results
        result = {
            'entity_id': entity_id,
            'timestamp': time.time(),
            'behavior_profile': asdict(behavior_profile),
            'attack_prediction': asdict(attack_prediction),
            'trust_score': new_trust,
            'risk_score': trust_record.get('risk_score', 0.0),
            'risk_level': trust_record.get('risk_level', 'low'),
            'asset_type': trust_record.get('asset_type', 'employee_device'),
            'asset_criticality': trust_record.get('asset_criticality', 1.0),
            'incident_type': trust_record.get('last_incident_type', 'behavior_anomaly'),
            'incident_severity': trust_record.get('last_incident_severity', 'low'),
            'correlation': asdict(correlation),
            'decision': decision,
            'ml_advisory': ml_advisory,
            'response': response_result,
            'status': 'analyzed'
        }
        
        return result
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics."""
        return {
            'total_entities_analyzed': len(self.entity_trust_scores),
            'active_responses': len(self.active_responses),
            'average_trust_score': sum(self.entity_trust_scores.values()) / len(self.entity_trust_scores) if self.entity_trust_scores else 100.0,
            'entities_by_trust': {
                'high_trust (>80)': len([s for s in self.entity_trust_scores.values() if s > 80]),
                'medium_trust (50-80)': len([s for s in self.entity_trust_scores.values() if 50 <= s <= 80]),
                'low_trust (<50)': len([s for s in self.entity_trust_scores.values() if s < 50])
            }
        }


def demo_scenario():
    """Run a demonstration scenario with various entity behaviors."""
    print("Cyber Defense System - Demo Scenario")
    print("=" * 50)
    
    # Initialize the system
    cds = CyberDefenseSystem()
    
    # Test entities with different behaviors
    test_entities = [
        {
            'entity_id': 'user_workstation_001',
            'data': {
                'connection_rate': 0.1,
                'request_rate': 0.2,
                'failed_auth_count': 0,
                'total_auth_count': 15,
                'unique_ports': 0.05,
                'sensitive_access_count': 0.0,
            }
        },
        {
            'entity_id': 'server_web_01',
            'data': {
                'connection_rate': 0.6,
                'request_rate': 0.8,
                'failed_auth_count': 8,
                'total_auth_count': 20,
                'unique_ports': 0.4,
                'sensitive_access_count': 0.2,
            }
        },
        {
            'entity_id': 'attacker_host_external',
            'data': {
                'connection_rate': 1.0,
                'request_rate': 1.0,
                'failed_auth_count': 95,
                'total_auth_count': 100,
                'unique_ports': 1.0,
                'sensitive_access_count': 0.9,
            }
        }
    ]
    
    # Analyze each entity
    results = []
    for entity in test_entities:
        result = cds.analyze_entity(entity['entity_id'], entity['data'])
        results.append(result)
        time.sleep(1)  # Brief pause between analyses
    
    # Show system status
    print("\n[System Status] Summary")
    print("=" * 30)
    status = cds.get_system_status()
    for key, value in status.items():
        print(f"{key}: {value}")
    
    return results, status


def interactive_mode():
    """Interactive mode for manual entity analysis."""
    print("\n[Interactive Mode]")
    print("Enter entity data for analysis (type 'quit' to exit)")
    
    cds = CyberDefenseSystem()
    
    while True:
        entity_id = input("\nEntity ID: ").strip()
        if entity_id.lower() == 'quit':
            break
        
        print("Enter entity data (comma-separated key=value pairs):")
        print("Example: connection_rate=0.5, failed_auth_count=10, total_auth_count=20")
        
        data_input = input("Data: ").strip()
        if data_input.lower() == 'quit':
            break
        
        try:
            # Parse input data
            entity_data = {}
            for pair in data_input.split(','):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    # Try to convert to float, otherwise keep as string
                    try:
                        entity_data[key] = float(value)
                    except ValueError:
                        entity_data[key] = value
            
            result = cds.analyze_entity(entity_id, entity_data)
            print(f"\n[Analysis complete] for {entity_id}")
            
        except Exception as e:
            print(f"[Error]: {e}")


def main():
    """Main entry point for cyber defense system."""
    print("[Cyber Defense System]")
    print("Running demo scenario automatically...")
    demo_scenario()


if __name__ == "__main__":
    main()
