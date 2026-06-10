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


def _safe_get_text(data: Mapping[str, Any], key: str) -> str:
    """Helper to read a text field safely from a mapping."""
    value = data.get(key, "")
    if value is None:
        return ""
    return str(value).strip()


def _clamp_unit(value: float) -> float:
    """Clamp a numeric value to the normalized [0, 1] range."""
    return max(0.0, min(1.0, float(value)))


def _count_distinct_values(value: Any) -> int:
    """Count distinct non-empty values from a scalar, CSV string or iterable."""
    if value is None:
        return 0

    if isinstance(value, str):
        raw_parts = [part.strip() for part in value.split(",")]
        return len({part for part in raw_parts if part})

    if isinstance(value, (list, tuple, set, frozenset)):
        normalized_values = set()
        for item in value:
            text = str(item).strip()
            if text:
                normalized_values.add(text)
        return len(normalized_values)

    text = str(value).strip()
    return 1 if text else 0


def _resolve_unique_source_ips(entity_data: Mapping[str, Any]) -> int:
    """Resolve how many distinct source IPs are participating in auth failures."""
    unique_source_ips = _safe_get_number(entity_data, "unique_source_ips", -1.0)
    if unique_source_ips >= 0.0:
        return max(0, int(unique_source_ips))

    ip_list_count = _count_distinct_values(entity_data.get("source_ips"))
    if ip_list_count > 0:
        return ip_list_count

    return 1 if _safe_get_text(entity_data, "source_ip") else 0


def _resolve_unique_target_users(entity_data: Mapping[str, Any]) -> int:
    """Resolve how many distinct target users were attacked in the time window."""
    unique_target_users = _safe_get_number(entity_data, "unique_target_users", -1.0)
    if unique_target_users >= 0.0:
        return max(0, int(unique_target_users))

    usernames_count = _count_distinct_values(entity_data.get("target_usernames"))
    if usernames_count > 0:
        return usernames_count

    usernames_count = _count_distinct_values(entity_data.get("usernames_attempted"))
    if usernames_count > 0:
        return usernames_count

    for key in ("target_username", "username", "user", "account_name"):
        if _safe_get_text(entity_data, key):
            return 1

    return 0


def _compute_targeted_brute_force_signal(
    entity_data: Mapping[str, Any],
    failed_auth_count: float,
    total_auth_count: float,
) -> float:
    """
    Estimate whether failed logins represent a targeted brute force pattern.

    The signal grows when:
    - failures are numerous
    - failures happen quickly in a short window
    - the attacker focuses on one or very few usernames
    - one or more source IPs repeatedly hit the same account
    """

    explicit_signal = _safe_get_number(entity_data, "targeted_brute_force_signal", -1.0)
    if explicit_signal >= 0.0:
        return _clamp_unit(explicit_signal)

    if failed_auth_count < 5.0:
        return 0.0

    window_seconds = max(
        1.0,
        _safe_get_number(
            entity_data,
            "failed_auth_window_seconds",
            _safe_get_number(entity_data, "auth_window_seconds", 900.0),
        ),
    )
    attempts_per_minute = failed_auth_count / max(1.0, window_seconds / 60.0)

    if total_auth_count > 0.0:
        auth_failure_factor = _clamp_unit(failed_auth_count / total_auth_count)
    else:
        auth_failure_factor = _clamp_unit(failed_auth_count / 12.0)

    unique_source_ips = _resolve_unique_source_ips(entity_data)
    unique_target_users = _resolve_unique_target_users(entity_data)
    has_explicit_target_user = any(
        _safe_get_text(entity_data, key)
        for key in ("target_username", "username", "user", "account_name")
    )

    # نحسب قوة التركيز على نفس الحساب بدل الرش العشوائي على عدة حسابات.
    if unique_target_users <= 1 and (unique_target_users == 1 or has_explicit_target_user):
        target_focus_factor = 1.0
    elif unique_target_users == 2:
        target_focus_factor = 0.7
    elif 0 < unique_target_users <= 3:
        target_focus_factor = 0.4
    else:
        target_focus_factor = 0.0

    # نعطي وزناً لتتبع الهجوم حسب الـ IP سواء كان من مصدر واحد أو عدة مصادر.
    if unique_source_ips >= 4:
        source_ip_factor = 1.0
    elif unique_source_ips == 3:
        source_ip_factor = 0.8
    elif unique_source_ips == 2:
        source_ip_factor = 0.6
    elif unique_source_ips == 1:
        source_ip_factor = 0.4
    else:
        source_ip_factor = 0.0

    signal = (
        0.30 * _clamp_unit(failed_auth_count / 15.0)
        + 0.25 * _clamp_unit(attempts_per_minute / 6.0)
        + 0.20 * auth_failure_factor
        + 0.15 * target_focus_factor
        + 0.10 * source_ip_factor
    )

    if target_focus_factor == 0.0:
        signal *= 0.55

    return _clamp_unit(signal)


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
    base += 30.0 * min(1.0, features.get("targeted_brute_force_signal", 0.0))

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
        - username / target_username: attacked username when known
        - source_ip / source_ips / unique_source_ips: attacking sources
        - unique_target_users / target_usernames: user focus in the attack window
        - failed_auth_window_seconds: time window used for failed login aggregation

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

    targeted_brute_force_signal = _compute_targeted_brute_force_signal(
        entity_data,
        failed_auth,
        total_auth,
    )

    # Reconnaissance / scanning features.
    unique_ports_contacted = max(0.0, _safe_get_number(entity_data, "unique_ports"))
    sensitive_resource_access = max(
        0.0, _safe_get_number(entity_data, "sensitive_access_count")
    )

    features: Dict[str, float] = {
        "connection_rate": connection_rate,
        "request_rate": request_rate,
        "failed_auth_ratio": failed_auth_ratio,
        "targeted_brute_force_signal": targeted_brute_force_signal,
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


