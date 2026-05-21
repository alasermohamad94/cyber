"""
Decision Engine Module

This module implements the decision-making logic for the cyber defense system.
It takes inputs from perception, prediction, and trust system to make security decisions.
"""

from typing import Dict, Any, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityDecision:
    """
    Security decision data structure.
    
    Attributes
    ----------
    action:
        The recommended action: 'monitor', 'alert', 'block', 'isolate'
    severity:
        Severity level: 'low', 'medium', 'high', 'critical'
    confidence:
        Decision confidence score [0, 1]
    reasoning:
        Human-readable explanation for the decision
    """
    action: str
    severity: str
    confidence: float
    reasoning: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'action': self.action,
            'severity': self.severity,
            'confidence': self.confidence,
            'reasoning': self.reasoning
        }


def _determine_action(behavior_score: float, attack_stage: str, trust_score: float) -> str:
    """
    Determine the appropriate security action based on multiple factors.
    
    Args:
        behavior_score: Behavior risk score [0, 100]
        attack_stage: Current attack stage prediction
        trust_score: Entity trust score [0, 100]
        
    Returns:
        Recommended action string
    """
    # Critical conditions - immediate isolation
    if (behavior_score >= 85 or 
        attack_stage in ['privilege_escalation', 'data_exfiltration'] or
        trust_score < 20):
        return 'isolate'
    
    # High-risk conditions - block
    if (behavior_score >= 70 or 
        attack_stage in ['lateral_movement'] or
        trust_score < 40):
        return 'block'
    
    # Medium-risk conditions - alert
    if (behavior_score >= 50 or 
        attack_stage in ['initial_access'] or
        trust_score < 60):
        return 'alert'
    
    # Low-risk - continue monitoring
    return 'monitor'


def _determine_severity(behavior_score: float, attack_stage: str) -> str:
    """
    Determine the severity level of the threat.
    
    Args:
        behavior_score: Behavior risk score [0, 100]
        attack_stage: Current attack stage prediction
        
    Returns:
        Severity level string
    """
    if behavior_score >= 85 or attack_stage in ['privilege_escalation', 'data_exfiltration']:
        return 'critical'
    elif behavior_score >= 70 or attack_stage == 'lateral_movement':
        return 'high'
    elif behavior_score >= 50 or attack_stage == 'initial_access':
        return 'medium'
    else:
        return 'low'


def _calculate_confidence(behavior_score: float, prediction_confidence: float, trust_score: float) -> float:
    """
    Calculate overall decision confidence.
    
    Args:
        behavior_score: Behavior risk score [0, 100]
        prediction_confidence: Attack prediction confidence [0, 1]
        trust_score: Entity trust score [0, 100]
        
    Returns:
        Overall confidence score [0, 1]
    """
    # Higher behavior scores and lower trust scores increase confidence
    behavior_factor = min(1.0, behavior_score / 100.0)
    trust_factor = 1.0 - (trust_score / 100.0)
    
    # Weighted average
    overall_confidence = (
        0.4 * behavior_factor +
        0.4 * prediction_confidence +
        0.2 * trust_factor
    )
    
    return round(min(1.0, max(0.0, overall_confidence)), 2)


def _generate_reasoning(behavior_score: float, attack_stage: str, trust_score: float, 
                       action: str, severity: str) -> str:
    """
    Generate human-readable reasoning for the decision.
    
    Args:
        behavior_score: Behavior risk score [0, 100]
        attack_stage: Current attack stage prediction
        trust_score: Entity trust score [0, 100]
        action: Recommended action
        severity: Threat severity
        
    Returns:
        Reasoning string
    """
    reasoning_parts = []
    
    # Behavior score reasoning
    if behavior_score >= 80:
        reasoning_parts.append(f"Extremely suspicious behavior detected (score: {behavior_score:.1f})")
    elif behavior_score >= 60:
        reasoning_parts.append(f"Suspicious behavior detected (score: {behavior_score:.1f})")
    elif behavior_score >= 40:
        reasoning_parts.append(f"Moderately unusual behavior (score: {behavior_score:.1f})")
    else:
        reasoning_parts.append(f"Normal behavior patterns (score: {behavior_score:.1f})")
    
    # Attack stage reasoning
    if attack_stage != 'normal':
        reasoning_parts.append(f"Entity appears to be in '{attack_stage}' attack stage")
    
    # Trust score reasoning
    if trust_score < 30:
        reasoning_parts.append(f"Very low trust score ({trust_score:.1f}) indicates high risk")
    elif trust_score < 60:
        reasoning_parts.append(f"Reduced trust score ({trust_score:.1f}) noted")
    else:
        reasoning_parts.append(f"Trust score remains acceptable ({trust_score:.1f})")
    
    # Action justification
    if action == 'isolate':
        reasoning_parts.append("Immediate isolation recommended to prevent potential damage")
    elif action == 'block':
        reasoning_parts.append("Blocking recommended to prevent further suspicious activity")
    elif action == 'alert':
        reasoning_parts.append("Security alert recommended for monitoring")
    else:
        reasoning_parts.append("Continue monitoring with standard procedures")
    
    return ". ".join(reasoning_parts) + "."


def make_decision(behavior_profile: Mapping[str, Any],
                 attack_prediction: Mapping[str, Any],
                 trust_score: float,
                 ml_advisory: Mapping[str, Any] = None) -> Dict[str, Any]:
    """
    Make a security decision based on behavior profile, attack prediction, and trust score.
    
    Args:
        behavior_profile: Output from perception layer
        attack_prediction: Output from prediction layer  
        trust_score: Current trust score for the entity
        
    Returns:
        Dictionary containing the security decision
    """
    # Extract key metrics
    if hasattr(behavior_profile, 'behavior_score'):
        behavior_score = getattr(behavior_profile, 'behavior_score')
    else:
        behavior_score = behavior_profile.get('behavior_score', 0.0)
    
    if hasattr(attack_prediction, 'current_stage'):
        attack_stage = getattr(attack_prediction, 'current_stage')
    else:
        attack_stage = attack_prediction.get('current_stage', 'normal')
    
    if hasattr(attack_prediction, 'confidence'):
        prediction_confidence = getattr(attack_prediction, 'confidence')
    else:
        prediction_confidence = attack_prediction.get('confidence', 0.0)
    
    # Validate inputs
    behavior_score = max(0.0, min(100.0, float(behavior_score)))
    trust_score = max(0.0, min(100.0, float(trust_score)))
    prediction_confidence = max(0.0, min(1.0, float(prediction_confidence)))
    
    # Make decision components
    action = _determine_action(behavior_score, attack_stage, trust_score)
    severity = _determine_severity(behavior_score, attack_stage)
    confidence = _calculate_confidence(behavior_score, prediction_confidence, trust_score)
    if ml_advisory and ml_advisory.get("enabled"):
        try:
            from prediction.model_inference import blend_confidence
            confidence = blend_confidence(confidence, dict(ml_advisory))
        except ImportError:
            pass

    reasoning = _generate_reasoning(behavior_score, attack_stage, trust_score, action, severity)
    if ml_advisory and ml_advisory.get("enabled"):
        reasoning += (
            f" ML shadow: {ml_advisory.get('anomaly_label', 'n/a')}"
            f" (advisory {ml_advisory.get('advisory_score', 0):.1f},"
            f" {ml_advisory.get('model_version', 'n/a')})."
        )
    
    # Create decision object
    decision = SecurityDecision(
        action=action,
        severity=severity,
        confidence=confidence,
        reasoning=reasoning
    )
    
    result = decision.to_dict()
    if ml_advisory:
        result["ml_advisory"] = dict(ml_advisory)
    return result


__all__ = ["SecurityDecision", "make_decision"]