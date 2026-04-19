"""
Unit tests for the behavioral analysis module in ``perception``.
"""

import os
import sys

# Ensure project root is on sys.path so that ``perception`` can be imported
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from perception.behavior_analysis import analyze_behavior, BehaviorProfile


def test_analyze_behavior_normal_case():
    """Entity with benign metrics should have low score and low anomaly level."""
    entity_data = {
        "connection_rate": 0.1,
        "request_rate": 0.1,
        "failed_auth_count": 0,
        "total_auth_count": 10,
        "unique_ports": 0.1,
        "sensitive_access_count": 0.0,
    }

    profile = analyze_behavior(entity_data)

    assert isinstance(profile, BehaviorProfile)
    assert 0.0 <= profile.behavior_score <= 40.0
    assert profile.anomaly_level == "low"


def test_analyze_behavior_suspicious_case():
    """Clearly malicious‑looking metrics should map to high/critical anomaly."""
    entity_data = {
        "connection_rate": 1.0,
        "request_rate": 1.0,
        "failed_auth_count": 90,
        "total_auth_count": 100,
        "unique_ports": 1.0,
        "sensitive_access_count": 1.0,
    }

    profile = analyze_behavior(entity_data)

    assert profile.behavior_score >= 70.0
    assert profile.anomaly_level in {"high", "critical"}


def test_analyze_behavior_handles_missing_fields_gracefully():
    """Missing or malformed fields should not raise and should default to safe values."""
    entity_data = {
        "connection_rate": "not-a-number",
        # other fields omitted intentionally
    }

    profile = analyze_behavior(entity_data)

    assert 0.0 <= profile.behavior_score <= 100.0
    assert profile.anomaly_level in {"low", "medium", "high", "critical"}


