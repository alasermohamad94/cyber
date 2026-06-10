"""Pipeline test: perception → ML shadow → decision."""

from main import CyberDefenseSystem


def test_analyze_entity_includes_ml_advisory():
    cds = CyberDefenseSystem()
    result = cds.analyze_entity(
        "test_entity_ml",
        {
            "asset_type": "database_server",
            "incident_type": "data_exfiltration",
            "incident_severity": "critical",
            "connection_rate": 0.9,
            "request_rate": 0.9,
            "failed_auth_count": 80,
            "total_auth_count": 90,
            "unique_ports": 0.9,
            "sensitive_access_count": 0.8,
        },
    )
    assert "ml_advisory" in result
    assert result["ml_advisory"].get("enabled") is True
    assert "decision" in result
    assert "risk_score" in result
    assert "risk_level" in result
    assert result["asset_type"] == "database_server"
    assert result["asset_criticality"] == 5.0
    assert result["incident_type"] == "data_exfiltration"
    assert result["incident_severity"] == "critical"
    assert "ml_advisory" in result["decision"] or result["decision"].get("ml_advisory")
    assert "policy_evaluation" in result["decision"]


def test_analyze_entity_exposes_targeted_brute_force_signal():
    cds = CyberDefenseSystem()
    result = cds.analyze_entity(
        "test_targeted_bruteforce",
        {
            "connection_rate": 0.2,
            "request_rate": 0.2,
            "failed_auth_count": 18,
            "total_auth_count": 20,
            "failed_auth_window_seconds": 120,
            "username": "admin",
            "source_ips": ["10.0.0.10", "10.0.0.11", "10.0.0.12"],
            "unique_target_users": 1,
        },
    )

    features = result["behavior_profile"]["features"]
    assert features["targeted_brute_force_signal"] >= 0.9
    assert result["behavior_profile"]["anomaly_level"] in {"high", "critical"}


def test_analyze_entity_exposes_distributed_scan_signal():
    cds = CyberDefenseSystem()
    result = cds.analyze_entity(
        "test_distributed_scan",
        {
            "connection_rate": 0.85,
            "request_rate": 0.4,
            "unique_ports": 0.95,
            "unique_source_ips": 5,
            "target_host": "db-core-01",
            "scan_window_seconds": 120,
            "incident_type": "distributed_scan",
            "incident_severity": "high",
        },
    )

    features = result["behavior_profile"]["features"]
    assert features["distributed_scan_signal"] >= 0.9
    assert result["behavior_profile"]["anomaly_level"] in {"high", "critical"}


def test_analyze_entity_exposes_exfiltration_signal():
    cds = CyberDefenseSystem()
    result = cds.analyze_entity(
        "test_exfiltration",
        {
            "connection_rate": 1.0,
            "request_rate": 1.0,
            "bytes_out": 500_000_000,
            "baseline_bytes_out": 50_000_000,
            "sensitive_access_count": 1.0,
            "external_destination_ratio": 1.0,
            "incident_type": "data_exfiltration",
            "incident_severity": "critical",
        },
    )

    features = result["behavior_profile"]["features"]
    assert features["exfiltration_signal"] >= 0.95
    assert result["behavior_profile"]["anomaly_level"] == "critical"
