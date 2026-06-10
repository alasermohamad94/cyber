"""
Decision Engine Module

This module implements the rule-based decision logic for the cyber defense
system. It takes inputs from perception, prediction, correlation, and trust
to determine the appropriate security response.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional


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
            "action": self.action,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


@dataclass(frozen=True)
class DecisionContext:
    """Normalized decision inputs used by the rule engine."""

    behavior_score: float
    attack_stage: str
    prediction_confidence: float
    trust_score: float
    risk_score: float
    risk_level: str
    correlation_type: str
    correlation_severity: str
    correlation_confidence: float
    correlation_detected: bool


@dataclass(frozen=True)
class DecisionRule:
    """Single rule used by the decision engine."""

    rule_id: str
    action: str
    severity: str
    priority: int
    description: str


def _safe_get_number(data: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    value = data.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_get_text(data: Mapping[str, Any], key: str, default: str = "") -> str:
    value = data.get(key, default)
    if value is None:
        return default
    return str(value).strip()


def _extract_behavior_score(behavior_profile: Mapping[str, Any]) -> float:
    """Extract behavior score from a dataclass or a dict-like object."""
    if hasattr(behavior_profile, "behavior_score"):
        value = getattr(behavior_profile, "behavior_score")
    else:
        value = behavior_profile.get("behavior_score", 0.0)
    try:
        return max(0.0, min(100.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _extract_prediction_stage(attack_prediction: Mapping[str, Any]) -> str:
    """Extract attack stage from a dataclass or dict-like object."""
    if hasattr(attack_prediction, "current_stage"):
        value = getattr(attack_prediction, "current_stage")
    else:
        value = attack_prediction.get("current_stage", "normal")
    return str(value or "normal").strip().lower()


def _extract_prediction_confidence(attack_prediction: Mapping[str, Any]) -> float:
    """Extract prediction confidence from a dataclass or dict-like object."""
    if hasattr(attack_prediction, "confidence"):
        value = getattr(attack_prediction, "confidence")
    else:
        value = attack_prediction.get("confidence", 0.0)
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _extract_correlation_context(
    correlation: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    if not correlation:
        return {
            "correlation_type": "",
            "correlation_severity": "low",
            "correlation_confidence": 0.0,
            "correlation_detected": False,
        }

    return {
        "correlation_type": _safe_get_text(correlation, "incident_type").lower(),
        "correlation_severity": _safe_get_text(
            correlation, "severity", "low"
        ).lower(),
        "correlation_confidence": max(
            0.0,
            min(1.0, _safe_get_number(correlation, "confidence", 0.0)),
        ),
        "correlation_detected": bool(correlation.get("correlated", False)),
    }


def _build_context(
    behavior_profile: Mapping[str, Any],
    attack_prediction: Mapping[str, Any],
    trust_score: float,
    correlation: Optional[Mapping[str, Any]] = None,
    risk_score: float = 0.0,
    risk_level: str = "low",
) -> DecisionContext:
    """Build a normalized decision context from pipeline inputs."""
    correlation_context = _extract_correlation_context(correlation)

    return DecisionContext(
        behavior_score=_extract_behavior_score(behavior_profile),
        attack_stage=_extract_prediction_stage(attack_prediction),
        prediction_confidence=_extract_prediction_confidence(attack_prediction),
        trust_score=max(0.0, min(100.0, float(trust_score))),
        risk_score=max(0.0, min(100.0, float(risk_score))),
        risk_level=str(risk_level or "low").strip().lower(),
        correlation_type=correlation_context["correlation_type"],
        correlation_severity=correlation_context["correlation_severity"],
        correlation_confidence=correlation_context["correlation_confidence"],
        correlation_detected=correlation_context["correlation_detected"],
    )


DECISION_RULES: List[DecisionRule] = [
    DecisionRule(
        rule_id="correlated_multi_stage_isolate",
        action="isolate",
        severity="critical",
        priority=100,
        description="Correlated multi-stage attack requires immediate isolation.",
    ),
    DecisionRule(
        rule_id="critical_intrusion_isolate",
        action="isolate",
        severity="critical",
        priority=90,
        description="Critical attack stage or collapsed trust requires isolation.",
    ),
    DecisionRule(
        rule_id="correlated_recon_block",
        action="block",
        severity="high",
        priority=80,
        description="Correlated reconnaissance and brute force requires blocking.",
    ),
    DecisionRule(
        rule_id="high_risk_block",
        action="block",
        severity="high",
        priority=70,
        description="High behavior or risk score requires blocking.",
    ),
    DecisionRule(
        rule_id="elevated_alert",
        action="alert",
        severity="medium",
        priority=60,
        description="Elevated behavior or initial access indicators require alerting.",
    ),
    DecisionRule(
        rule_id="default_monitor",
        action="monitor",
        severity="low",
        priority=0,
        description="No stronger policy matched, continue monitoring.",
    ),
]


def _matches_correlated_multi_stage_isolate(context: DecisionContext) -> bool:
    return context.correlation_detected and context.correlation_type in {
        "multi_stage_attack",
        "credential_compromise_exfiltration",
    }


def _matches_critical_intrusion_isolate(context: DecisionContext) -> bool:
    return (
        context.behavior_score >= 85.0
        or context.attack_stage in {"privilege_escalation", "data_exfiltration"}
        or context.trust_score < 20.0
        or context.risk_score >= 90.0
    )


def _matches_correlated_recon_block(context: DecisionContext) -> bool:
    return context.correlation_detected and context.correlation_type == (
        "recon_to_initial_access"
    )


def _matches_high_risk_block(context: DecisionContext) -> bool:
    return (
        context.behavior_score >= 70.0
        or context.attack_stage == "lateral_movement"
        or context.trust_score < 40.0
        or context.risk_score >= 75.0
        or context.risk_level in {"high", "critical"}
    )


def _matches_elevated_alert(context: DecisionContext) -> bool:
    return (
        context.behavior_score >= 50.0
        or context.attack_stage == "initial_access"
        or context.trust_score < 60.0
        or context.risk_score >= 50.0
        or context.correlation_detected
    )


RULE_PREDICATES: Dict[str, Callable[[DecisionContext], bool]] = {
    "correlated_multi_stage_isolate": _matches_correlated_multi_stage_isolate,
    "critical_intrusion_isolate": _matches_critical_intrusion_isolate,
    "correlated_recon_block": _matches_correlated_recon_block,
    "high_risk_block": _matches_high_risk_block,
    "elevated_alert": _matches_elevated_alert,
    "default_monitor": lambda _context: True,
}


def _evaluate_decision_rules(context: DecisionContext) -> DecisionRule:
    """Return the highest-priority matched decision rule."""
    matched_rules = [
        rule
        for rule in DECISION_RULES
        if RULE_PREDICATES[rule.rule_id](context)
    ]
    return max(matched_rules, key=lambda rule: rule.priority)


def _calculate_confidence(
    context: DecisionContext,
    ml_advisory: Optional[Mapping[str, Any]] = None,
) -> float:
    """
    Calculate overall decision confidence.

    Higher behavior and risk scores, plus lower trust, increase confidence.
    Correlated incidents raise confidence because several detections agree.
    """

    behavior_factor = min(1.0, context.behavior_score / 100.0)
    trust_factor = 1.0 - (context.trust_score / 100.0)
    risk_factor = min(1.0, context.risk_score / 100.0)
    correlation_factor = (
        context.correlation_confidence if context.correlation_detected else 0.0
    )

    confidence = (
        0.25 * behavior_factor
        + 0.30 * context.prediction_confidence
        + 0.20 * trust_factor
        + 0.15 * risk_factor
        + 0.10 * correlation_factor
    )
    confidence = round(min(1.0, max(0.0, confidence)), 2)

    if ml_advisory and ml_advisory.get("enabled"):
        try:
            from prediction.model_inference import blend_confidence

            confidence = blend_confidence(confidence, dict(ml_advisory))
        except ImportError:
            pass

    return confidence


def _generate_reasoning(
    context: DecisionContext,
    selected_rule: DecisionRule,
) -> str:
    """Generate a human-readable explanation for the selected rule."""
    reasoning_parts = [selected_rule.description]

    if context.behavior_score >= 80.0:
        reasoning_parts.append(
            f"Extremely suspicious behavior detected (score: {context.behavior_score:.1f})"
        )
    elif context.behavior_score >= 60.0:
        reasoning_parts.append(
            f"Suspicious behavior detected (score: {context.behavior_score:.1f})"
        )
    elif context.behavior_score >= 40.0:
        reasoning_parts.append(
            f"Moderately unusual behavior (score: {context.behavior_score:.1f})"
        )
    else:
        reasoning_parts.append(
            f"Normal behavior patterns (score: {context.behavior_score:.1f})"
        )

    if context.attack_stage != "normal":
        reasoning_parts.append(
            f"Entity appears to be in '{context.attack_stage}' attack stage"
        )

    if context.risk_score >= 75.0:
        reasoning_parts.append(
            f"Risk engine raised the entity score to {context.risk_score:.1f}"
        )
    elif context.risk_score >= 50.0:
        reasoning_parts.append(
            f"Risk engine reports elevated pressure ({context.risk_score:.1f})"
        )

    if context.correlation_detected:
        reasoning_parts.append(
            f"Correlation engine linked this activity to '{context.correlation_type}'"
        )

    if context.trust_score < 30.0:
        reasoning_parts.append(
            f"Very low trust score ({context.trust_score:.1f}) indicates high risk"
        )
    elif context.trust_score < 60.0:
        reasoning_parts.append(
            f"Reduced trust score ({context.trust_score:.1f}) noted"
        )
    else:
        reasoning_parts.append(
            f"Trust score remains acceptable ({context.trust_score:.1f})"
        )

    if selected_rule.action == "isolate":
        reasoning_parts.append(
            "Immediate isolation recommended to prevent potential damage"
        )
    elif selected_rule.action == "block":
        reasoning_parts.append(
            "Blocking recommended to prevent further suspicious activity"
        )
    elif selected_rule.action == "alert":
        reasoning_parts.append("Security alert recommended for monitoring")
    else:
        reasoning_parts.append("Continue monitoring with standard procedures")

    return ". ".join(reasoning_parts) + "."


def make_decision(
    behavior_profile: Mapping[str, Any],
    attack_prediction: Mapping[str, Any],
    trust_score: float,
    ml_advisory: Optional[Mapping[str, Any]] = None,
    correlation: Optional[Mapping[str, Any]] = None,
    risk_score: float = 0.0,
    risk_level: str = "low",
) -> Dict[str, Any]:
    """
    Make a security decision based on behavior, prediction, trust, and correlation.

    Parameters
    ----------
    behavior_profile:
        Output from the perception layer.
    attack_prediction:
        Output from the prediction layer.
    trust_score:
        Current trust score for the entity.
    ml_advisory:
        Optional shadow-ML advisory payload.
    correlation:
        Optional correlation-engine output.
    risk_score:
        Risk score computed by the trust/risk engine.
    risk_level:
        Human-readable risk level.
    """

    context = _build_context(
        behavior_profile,
        attack_prediction,
        trust_score,
        correlation=correlation,
        risk_score=risk_score,
        risk_level=risk_level,
    )
    selected_rule = _evaluate_decision_rules(context)
    confidence = _calculate_confidence(context, ml_advisory)
    reasoning = _generate_reasoning(context, selected_rule)

    if ml_advisory and ml_advisory.get("enabled"):
        reasoning += (
            f" ML shadow: {ml_advisory.get('anomaly_label', 'n/a')}"
            f" (advisory {ml_advisory.get('advisory_score', 0):.1f},"
            f" {ml_advisory.get('model_version', 'n/a')})."
        )

    decision = SecurityDecision(
        action=selected_rule.action,
        severity=selected_rule.severity,
        confidence=confidence,
        reasoning=reasoning,
    )

    result = decision.to_dict()
    if ml_advisory:
        result["ml_advisory"] = dict(ml_advisory)
    return result


__all__ = [
    "DecisionContext",
    "DecisionRule",
    "SecurityDecision",
    "make_decision",
]
