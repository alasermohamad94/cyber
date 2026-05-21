"""
Shadow-mode ML inference (P3).

- Default: advisory only (does not change automated actions).
- CDS_ML_CANARY=true: may adjust decision confidence via decision_engine.
- Uses IsolationForest when scikit-learn is installed; otherwise heuristic baseline.
"""

import os
from typing import Any, Dict, List, Optional


def ml_shadow_enabled() -> bool:
    return os.environ.get("CDS_ML_SHADOW_MODE", "true").lower() in ("1", "true", "yes")


def ml_canary_enabled() -> bool:
    return os.environ.get("CDS_ML_CANARY", "false").lower() in ("1", "true", "yes")


_MODEL = None
_MODEL_VERSION = "heuristic-v1"


def _sklearn_available() -> bool:
    try:
        import sklearn  # noqa: F401
        return True
    except ImportError:
        return False


def _get_isolation_forest():
    global _MODEL, _MODEL_VERSION
    if _MODEL is not None:
        return _MODEL
    if not _sklearn_available():
        return None
    from sklearn.ensemble import IsolationForest
    import numpy as np

    # Baseline fit on normal traffic patterns (synthetic until real telemetry labels exist)
    rng = np.random.RandomState(42)
    normal = rng.normal(loc=0.2, scale=0.15, size=(200, 6))
    normal = np.clip(normal, 0, 1)
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(normal)
    _MODEL = model
    _MODEL_VERSION = "isolation-forest-v1"
    return _MODEL


def build_feature_vector(entity_data: Dict[str, Any], behavior_score: float) -> List[float]:
    return [
        float(entity_data.get("connection_rate", 0)),
        float(entity_data.get("request_rate", 0)),
        float(entity_data.get("failed_auth_count", 0)) / max(1.0, float(entity_data.get("total_auth_count", 1))),
        float(entity_data.get("unique_ports", 0)),
        float(entity_data.get("sensitive_access_count", 0)),
        behavior_score / 100.0,
    ]


def shadow_predict(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce ML advisory output. Does not execute responses by itself.
    """
    if not ml_shadow_enabled():
        return {"mode": "disabled", "enabled": False}

    vector = features.get("feature_vector")
    behavior = float(features.get("behavior_score", 0))

    if vector is None:
        entity_data = features.get("entity_data", {})
        vector = build_feature_vector(entity_data, behavior)

    model = _get_isolation_forest()
    anomaly_score = behavior * 0.85
    label = "normal"

    if model is not None:
        import numpy as np
        pred = model.predict([vector])[0]
        raw = float(model.decision_function([vector])[0])
        # IsolationForest: -1 = anomaly
        if pred == -1:
            label = "anomaly"
            anomaly_score = min(100.0, 50.0 + abs(raw) * 40.0)
        else:
            label = "normal"
            anomaly_score = min(100.0, max(0.0, 30.0 - abs(raw) * 20.0))
    else:
        if behavior >= 70:
            label = "anomaly"
            anomaly_score = behavior * 0.9

    return {
        "mode": "shadow",
        "enabled": True,
        "canary_active": ml_canary_enabled(),
        "advisory_score": round(anomaly_score, 2),
        "anomaly_label": label,
        "model_version": _MODEL_VERSION,
        "feature_vector": vector,
    }


def blend_confidence(rule_confidence: float, ml_advisory: Optional[Dict[str, Any]]) -> float:
    """Blend rule confidence with ML advisory when canary mode is on."""
    if not ml_advisory or not ml_advisory.get("enabled"):
        return rule_confidence
    if not ml_canary_enabled():
        return rule_confidence
    ml_factor = float(ml_advisory.get("advisory_score", 0)) / 100.0
    blended = 0.7 * rule_confidence + 0.3 * ml_factor
    return round(min(1.0, max(0.0, blended)), 2)
