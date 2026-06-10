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


def test_analyze_behavior_detects_targeted_brute_force():
    """Repeated failures against one user in a short window should be flagged strongly."""
    entity_data = {
        "connection_rate": 0.15,
        "request_rate": 0.2,
        "failed_auth_count": 18,
        "total_auth_count": 20,
        "failed_auth_window_seconds": 120,
        "username": "admin",
        "unique_source_ips": 3,
        "unique_target_users": 1,
    }

    profile = analyze_behavior(entity_data)

    assert profile.features is not None
    assert profile.features["targeted_brute_force_signal"] >= 0.9
    assert profile.behavior_score >= 50.0
    assert profile.anomaly_level in {"high", "critical"}


def test_analyze_behavior_reduces_signal_for_password_spray():
    """Attacking many usernames should look less targeted than a focused brute force."""
    entity_data = {
        "failed_auth_count": 18,
        "total_auth_count": 20,
        "failed_auth_window_seconds": 120,
        "unique_source_ips": 3,
        "unique_target_users": 12,
        "target_usernames": [
            "admin",
            "finance",
            "ops",
            "root",
            "user01",
            "user02",
            "user03",
            "user04",
            "user05",
            "user06",
            "user07",
            "user08",
        ],
    }

    profile = analyze_behavior(entity_data)

    assert profile.features is not None
    assert profile.features["targeted_brute_force_signal"] < 0.5
    assert profile.anomaly_level in {"medium", "high"}


def test_analyze_behavior_detects_distributed_port_scan():
    """Scanning many ports from several IPs should be stronger than single-source probing."""
    distributed_scan = analyze_behavior(
        {
            "connection_rate": 0.85,
            "request_rate": 0.4,
            "unique_ports": 0.95,
            "unique_source_ips": 5,
            "target_host": "db-core-01",
            "scan_window_seconds": 120,
        }
    )
    single_source_scan = analyze_behavior(
        {
            "connection_rate": 0.85,
            "request_rate": 0.4,
            "unique_ports": 0.95,
            "source_ip": "10.0.0.5",
            "target_host": "db-core-01",
            "scan_window_seconds": 120,
        }
    )

    assert distributed_scan.features is not None
    assert single_source_scan.features is not None
    assert distributed_scan.features["distributed_scan_signal"] >= 0.9
    assert single_source_scan.features["distributed_scan_signal"] < 0.5
    assert distributed_scan.behavior_score > single_source_scan.behavior_score
    assert distributed_scan.anomaly_level in {"high", "critical"}


def test_analyze_behavior_detects_exfiltration_above_baseline():
    """Outbound data far above baseline should trigger a strong exfiltration signal."""
    profile = analyze_behavior(
        {
            "connection_rate": 1.0,
            "request_rate": 1.0,
            "bytes_out": 500_000_000,
            "baseline_bytes_out": 50_000_000,
            "sensitive_access_count": 1.0,
            "external_destination_ratio": 1.0,
        }
    )

    assert profile.features is not None
    assert profile.features["exfiltration_signal"] >= 0.95
    assert profile.behavior_score >= 85.0
    assert profile.anomaly_level == "critical"


def test_analyze_behavior_reduces_exfiltration_signal_near_baseline():
    """Outbound traffic close to baseline should not look like severe exfiltration."""
    profile = analyze_behavior(
        {
            "bytes_out": 60_000_000,
            "baseline_bytes_out": 50_000_000,
            "sensitive_access_count": 0.2,
            "external_destination_ratio": 0.1,
        }
    )

    assert profile.features is not None
    assert profile.features["exfiltration_signal"] < 0.2
    assert profile.anomaly_level in {"low", "medium"}


