"""
Tests for the attack prediction module.
"""

from perception.behavior_analysis import analyze_behavior
from prediction.attack_prediction import AttackPrediction, predict_attack


def test_predict_attack_uses_perception_output_only():
    """
    End‑to‑end style scenario:

    - build a behavior profile using the perception layer
    - feed it into the prediction layer

    Ensures integration between modules without modifying other modules.
    """
    # Simulate a suspicious entity with high failed authentication rate and
    # scanning behaviour.
    entity_data = {
        "connection_rate": 0.8,
        "request_rate": 0.9,
        "failed_auth_count": 15,
        "total_auth_count": 20,
        "unique_ports": 0.9,
        "sensitive_access_count": 0.7,
    }

    behavior_profile = analyze_behavior(entity_data)
    prediction = predict_attack(behavior_profile)

    assert isinstance(prediction, AttackPrediction)
    # For such suspicious behaviour we expect to be at least beyond "normal".
    assert prediction.current_stage != "normal"
    assert 0.0 <= prediction.confidence <= 1.0


def test_predict_attack_progression_for_low_score():
    """Low scores should keep the entity in the 'normal' stage with no next stage."""
    behavior_profile = {"behavior_score": 5.0}

    prediction = predict_attack(behavior_profile)

    assert prediction.current_stage == "normal"
    assert prediction.next_stage is None
    assert 0.0 <= prediction.confidence < 0.2


