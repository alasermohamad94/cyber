"""Tests for the rule-based decision and policy-evaluation engine."""

from decision_engine.descision_engine import evaluate_policies, make_decision


def _behavior_profile(score: float) -> dict:
    return {"behavior_score": score, "anomaly_level": "medium", "features": {}}


def _attack_prediction(stage: str, confidence: float = 0.7) -> dict:
    return {"current_stage": stage, "confidence": confidence}


def test_make_decision_monitors_normal_activity():
    decision = make_decision(
        _behavior_profile(10.0),
        _attack_prediction("normal", 0.1),
        trust_score=95.0,
        risk_score=5.0,
        risk_level="low",
    )

    assert decision["action"] == "monitor"
    assert decision["severity"] == "low"


def test_make_decision_alerts_for_initial_access():
    decision = make_decision(
        _behavior_profile(42.0),
        _attack_prediction("initial_access", 0.6),
        trust_score=82.0,
        risk_score=35.0,
        risk_level="medium",
    )

    assert decision["action"] == "alert"
    assert decision["severity"] == "medium"


def test_make_decision_blocks_for_high_risk_score():
    decision = make_decision(
        _behavior_profile(35.0),
        _attack_prediction("normal", 0.5),
        trust_score=78.0,
        risk_score=82.0,
        risk_level="high",
    )

    assert decision["action"] == "block"
    assert decision["severity"] == "high"


def test_make_decision_blocks_for_correlated_reconnaissance():
    decision = make_decision(
        _behavior_profile(38.0),
        _attack_prediction("reconnaissance", 0.6),
        trust_score=74.0,
        correlation={
            "correlated": True,
            "incident_type": "recon_to_initial_access",
            "severity": "high",
            "confidence": 0.85,
        },
        risk_score=45.0,
        risk_level="medium",
    )

    assert decision["action"] == "block"
    assert decision["severity"] == "high"
    assert "Correlation engine linked this activity" in decision["reasoning"]


def test_make_decision_isolates_for_multi_stage_attack():
    decision = make_decision(
        _behavior_profile(58.0),
        _attack_prediction("initial_access", 0.8),
        trust_score=52.0,
        correlation={
            "correlated": True,
            "incident_type": "multi_stage_attack",
            "severity": "critical",
            "confidence": 0.92,
        },
        risk_score=88.0,
        risk_level="critical",
    )

    assert decision["action"] == "isolate"
    assert decision["severity"] == "critical"
    assert decision["confidence"] >= 0.7


def test_evaluate_policies_returns_selected_rule_and_trace():
    evaluation = evaluate_policies(
        _behavior_profile(38.0),
        _attack_prediction("reconnaissance", 0.6),
        trust_score=74.0,
        correlation={
            "correlated": True,
            "incident_type": "recon_to_initial_access",
            "severity": "high",
            "confidence": 0.85,
        },
        risk_score=45.0,
        risk_level="medium",
    )

    assert evaluation.selected_rule_id == "correlated_recon_block"
    assert evaluation.selected_action == "block"
    assert "correlated_recon_block" in evaluation.matched_rules
    assert "elevated_alert" in evaluation.matched_rules
    assert evaluation.context_snapshot["correlation_detected"] is True


def test_make_decision_includes_policy_evaluation_payload():
    decision = make_decision(
        _behavior_profile(35.0),
        _attack_prediction("normal", 0.5),
        trust_score=78.0,
        risk_score=82.0,
        risk_level="high",
    )

    assert "policy_evaluation" in decision
    assert decision["policy_evaluation"]["selected_rule_id"] == "high_risk_block"
    assert decision["policy_evaluation"]["selected_action"] == "block"
