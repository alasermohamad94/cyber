"""
Behavioral Analysis Module (Perception Layer).

This module is responsible for analyzing raw entity telemetry and producing
an aggregated behavior profile. The core public entrypoint is
``analyze_behavior(entity_data)`` which computes:

- behavior_score: numeric risk score in the range [0, 100]
- anomaly_level: categorical level: \"low\", \"medium\", \"high\", or \"critical\"

The function is intentionally lightweight and deterministic so it can be
used safely by higher layers such as the prediction and decision engine
modules.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Mapping, Optional


@dataclass(frozen=True)
class BehaviorProfile:
    """
    Normalized behavior profile for a single entity.

    Attributes
    ----------
    behavior_score:
        Overall risk score in the range [0, 100]. Higher means more suspicious.
    anomaly_level:
        Categorical level derived from ``behavior_score``:
        - \"low\"      : score   < 25
        - \"medium\"   : 25 <= score < 50
        - \"high\"     : 50 <= score < 75
        - \"critical\" : score  >= 75
    features:
        Optional normalized feature values that were used to compute the score.
        This is useful for explainability, debugging and for the prediction
        module which may consume richer context in the future.
    """

    behavior_score: float
    anomaly_level: str
    features: Optional[Dict[str, float]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the profile to a plain dictionary."""
        return asdict(self)


def _safe_get_number(data: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    """Helper to read a numeric feature safely from a mapping."""
    value = data.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _compute_behavior_score(features: Mapping[str, float]) -> float:
    """
    Compute an aggregated behavior score from normalized features.

    The scoring logic is intentionally simple but captures common suspicious
    patterns such as:
    - excessive connection / request rates
    - many failed authentications
    - port scanning or lateral movement indicators
    """

    # Base score from traffic volume and request rate.
    base = 0.0
    base += 20.0 * min(1.0, features.get("connection_rate", 0.0))
    base += 15.0 * min(1.0, features.get("request_rate", 0.0))

    # Authentication anomalies.
    base += 25.0 * min(1.0, features.get("failed_auth_ratio", 0.0))

    # Recon / scanning behaviour.
    base += 20.0 * min(1.0, features.get("unique_ports_contacted", 0.0))
    base += 10.0 * min(1.0, features.get("sensitive_resource_access", 0.0))

    # Clamp to [0, 100]
    return max(0.0, min(100.0, base))


def _map_score_to_anomaly_level(score: float) -> str:
    """Map a numeric behavior score to a human‑readable anomaly level."""
    if score < 25.0:
        return "low"
    if score < 50.0:
        return "medium"
    if score < 75.0:
        return "high"
    return "critical"


def analyze_behavior(entity_data: Mapping[str, Any]) -> BehaviorProfile:
    """
    Analyze raw entity telemetry and compute a behavior profile.

    Parameters
    ----------
    entity_data:
        Dictionary-like object containing telemetry about a single entity
        (host, user, service, etc.). All fields are optional; unknown or
        malformed values are treated as zero / non-suspicious.

        Supported fields (all expected to be non‑negative numbers):
        - connection_rate: connections per second, normalized to [0, 1]
        - request_rate: requests per second, normalized to [0, 1]
        - failed_auth_count: number of failed logins in the window
        - total_auth_count: total login attempts in the window
        - unique_ports: number of distinct destination ports contacted (normalized)
        - sensitive_access_count: accesses to high‑value resources (normalized)

    Returns
    -------
    BehaviorProfile
        Dataclass with ``behavior_score`` and ``anomaly_level`` as required
        by the project specification.
    """

    if not isinstance(entity_data, Mapping):
        raise TypeError("entity_data must be a mapping/dict‑like object")

    # Basic rate features (expected already roughly normalized).
    connection_rate = max(0.0, _safe_get_number(entity_data, "connection_rate"))
    request_rate = max(0.0, _safe_get_number(entity_data, "request_rate"))

    # Authentication anomaly ratio.
    failed_auth = max(0.0, _safe_get_number(entity_data, "failed_auth_count"))
    total_auth = max(0.0, _safe_get_number(entity_data, "total_auth_count"))
    if total_auth > 0:
        failed_auth_ratio = min(1.0, failed_auth / total_auth)
    else:
        failed_auth_ratio = 0.0

    # Reconnaissance / scanning features.
    unique_ports_contacted = max(0.0, _safe_get_number(entity_data, "unique_ports"))
    sensitive_resource_access = max(
        0.0, _safe_get_number(entity_data, "sensitive_access_count")
    )

    features: Dict[str, float] = {
        "connection_rate": connection_rate,
        "request_rate": request_rate,
        "failed_auth_ratio": failed_auth_ratio,
        "unique_ports_contacted": unique_ports_contacted,
        "sensitive_resource_access": sensitive_resource_access,
    }

    behavior_score = _compute_behavior_score(features)
    anomaly_level = _map_score_to_anomaly_level(behavior_score)

    return BehaviorProfile(
        behavior_score=behavior_score,
        anomaly_level=anomaly_level,
        features=features,
    )


__all__ = ["BehaviorProfile", "analyze_behavior"]


