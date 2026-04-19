"""
Attack Prediction Module.

This module implements ``predict_attack(behavior_profile)`` which consumes
the output of the perception layer and predicts:

- current_stage: the most likely current phase of the attack lifecycle
- next_stage: the most probable upcoming phase (or ``None`` if not applicable)

The function is designed to be pure and side‑effect free; it only operates
on the provided behavior profile and does not modify any external modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional


# A simple, interpretable lifecycle tailored to this project.
ATTACK_STAGES = [
    "normal",
    "reconnaissance",
    "initial_access",
    "lateral_movement",
    "privilege_escalation",
    "data_exfiltration",
]


@dataclass(frozen=True)
class AttackPrediction:
    """
    Prediction result for a single entity.

    Attributes
    ----------
    current_stage:
        The inferred current stage in the attack lifecycle.
    next_stage:
        The most plausible upcoming stage or ``None`` if the entity is
        considered benign / in a stable state.
    confidence:
        Confidence score in the range [0, 1] derived from the
        ``behavior_score`` and anomaly level.
    """

    current_stage: str
    next_stage: Optional[str]
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert the prediction to a plain dictionary."""
        return {
            "current_stage": self.current_stage,
            "next_stage": self.next_stage,
            "confidence": self.confidence,
        }


def _extract_behavior_score(profile: Mapping[str, Any]) -> float:
    """
    Read the behavior score from either a dict or a dataclass‑like object.

    The perception layer exposes ``BehaviorProfile`` with a ``behavior_score``
    field, but the prediction module is intentionally tolerant to receive a
    simple dict as well (e.g. when serialized / deserialized).
    """
    if hasattr(profile, "behavior_score"):
        value = getattr(profile, "behavior_score")
    else:
        value = profile.get("behavior_score", 0.0)  # type: ignore[assignment]
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _stage_from_score(score: float) -> str:
    """
    Map behavior score (0‑100) to a coarse attack stage.

    The mapping is intentionally simple and monotonic:
    - [0, 20)   -> normal
    - [20, 40)  -> reconnaissance
    - [40, 60)  -> initial_access
    - [60, 80)  -> lateral_movement
    - [80, 90)  -> privilege_escalation
    - [90, 100] -> data_exfiltration
    """
    if score < 20.0:
        return "normal"
    if score < 40.0:
        return "reconnaissance"
    if score < 60.0:
        return "initial_access"
    if score < 80.0:
        return "lateral_movement"
    if score < 90.0:
        return "privilege_escalation"
    return "data_exfiltration"


def _next_stage(current_stage: str) -> Optional[str]:
    """Return the next logical stage in the attack lifecycle, if any."""
    try:
        idx = ATTACK_STAGES.index(current_stage)
    except ValueError:
        return None

    if idx <= 0:
        # From normal we don't commit to a specific next step.
        return None
    if idx >= len(ATTACK_STAGES) - 1:
        return None
    return ATTACK_STAGES[idx + 1]


def _confidence_from_score(score: float) -> float:
    """
    Derive a simple confidence estimate from the behavior score.

    Higher scores indicate clearer malicious behavior and therefore higher
    prediction confidence.
    """
    if score <= 0:
        return 0.0
    if score >= 100:
        return 1.0
    return round(score / 100.0, 2)


def predict_attack(behavior_profile: Mapping[str, Any]) -> AttackPrediction:
    """
    Predict current and upcoming attack stages from a behavior profile.

    Parameters
    ----------
    behavior_profile:
        The output object produced by the perception module. The predictor
        only relies on the ``behavior_score`` field and does not mutate
        the profile or any external modules.

    Returns
    -------
    AttackPrediction
        Dataclass containing current_stage, next_stage and a confidence
        value in [0, 1].
    """
    if not isinstance(behavior_profile, Mapping) and not hasattr(
        behavior_profile, "behavior_score"
    ):
        raise TypeError(
            "behavior_profile must be a mapping/dict‑like or an object with "
            "a 'behavior_score' attribute"
        )

    score = _extract_behavior_score(behavior_profile)
    score = max(0.0, min(100.0, score))

    current = _stage_from_score(score)
    nxt = _next_stage(current)
    confidence = _confidence_from_score(score)

    return AttackPrediction(current_stage=current, next_stage=nxt, confidence=confidence)


__all__ = ["AttackPrediction", "predict_attack", "ATTACK_STAGES"]


