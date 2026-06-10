"""Tests for the threat correlation engine."""

import os
import sys

# Ensure project root is on sys.path so local modules can be imported
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from correlation.threat_correlation import ThreatCorrelationEngine
from main import CyberDefenseSystem
from perception.behavior_analysis import analyze_behavior


def test_engine_correlates_scan_then_brute_force_from_same_ip():
    engine = ThreatCorrelationEngine()
    scan_data = {
        "source_ip": "203.0.113.10",
        "connection_rate": 0.85,
        "request_rate": 0.4,
        "unique_ports": 0.95,
        "unique_source_ips": 5,
        "target_host": "db-core-01",
        "scan_window_seconds": 120,
    }
    brute_force_data = {
        "source_ip": "203.0.113.10",
        "connection_rate": 0.2,
        "request_rate": 0.2,
        "failed_auth_count": 18,
        "total_auth_count": 20,
        "failed_auth_window_seconds": 120,
        "username": "admin",
        "unique_target_users": 1,
    }

    first = engine.analyze(
        "scan_entity",
        scan_data,
        analyze_behavior(scan_data),
        analysis_timestamp=1_000.0,
    )
    second = engine.analyze(
        "auth_entity",
        brute_force_data,
        analyze_behavior(brute_force_data),
        analysis_timestamp=1_120.0,
    )

    assert first.correlated is False
    assert second.correlated is True
    assert second.incident_type == "recon_to_initial_access"
    assert second.source_ip == "203.0.113.10"
    assert second.matched_event_types == ["distributed_scan", "targeted_brute_force"]
    assert second.related_entities == ["scan_entity", "auth_entity"]
    assert second.time_window_seconds == 900


def test_engine_does_not_correlate_when_window_expires():
    engine = ThreatCorrelationEngine()
    scan_data = {
        "source_ip": "203.0.113.50",
        "unique_ports": 0.9,
        "unique_source_ips": 4,
        "target_host": "app-01",
    }
    brute_force_data = {
        "source_ip": "203.0.113.50",
        "failed_auth_count": 20,
        "total_auth_count": 22,
        "failed_auth_window_seconds": 120,
        "username": "admin",
        "unique_target_users": 1,
    }

    engine.analyze(
        "scan_entity",
        scan_data,
        analyze_behavior(scan_data),
        analysis_timestamp=1_000.0,
    )
    late_result = engine.analyze(
        "auth_entity",
        brute_force_data,
        analyze_behavior(brute_force_data),
        analysis_timestamp=2_000.0,
    )

    assert late_result.correlated is False
    assert late_result.incident_type is None


def test_cyber_defense_system_exposes_correlation_result():
    cds = CyberDefenseSystem()
    cds.analyze_entity(
        "scan_entity",
        {
            "source_ip": "198.51.100.20",
            "connection_rate": 0.85,
            "request_rate": 0.4,
            "unique_ports": 0.95,
            "unique_source_ips": 5,
            "target_host": "db-core-01",
            "scan_window_seconds": 120,
        },
    )
    result = cds.analyze_entity(
        "auth_entity",
        {
            "source_ip": "198.51.100.20",
            "connection_rate": 0.2,
            "request_rate": 0.2,
            "failed_auth_count": 18,
            "total_auth_count": 20,
            "failed_auth_window_seconds": 120,
            "username": "admin",
            "unique_target_users": 1,
        },
    )

    assert "correlation" in result
    assert result["correlation"]["correlated"] is True
    assert result["correlation"]["incident_type"] == "recon_to_initial_access"
    assert result["correlation"]["source_ip"] == "198.51.100.20"


def test_engine_correlates_brute_force_then_exfiltration():
    engine = ThreatCorrelationEngine()
    brute_force_data = {
        "source_ip": "192.0.2.10",
        "failed_auth_count": 20,
        "total_auth_count": 21,
        "failed_auth_window_seconds": 120,
        "username": "finance-admin",
        "unique_target_users": 1,
    }
    exfiltration_data = {
        "source_ip": "192.0.2.10",
        "bytes_out": 500_000_000,
        "baseline_bytes_out": 50_000_000,
        "sensitive_access_count": 1.0,
        "external_destination_ratio": 1.0,
    }

    engine.analyze(
        "auth_entity",
        brute_force_data,
        analyze_behavior(brute_force_data),
        analysis_timestamp=2_000.0,
    )
    result = engine.analyze(
        "db_entity",
        exfiltration_data,
        analyze_behavior(exfiltration_data),
        analysis_timestamp=2_180.0,
    )

    assert result.correlated is True
    assert result.incident_type == "credential_compromise_exfiltration"
    assert result.severity == "critical"
