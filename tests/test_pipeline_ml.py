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
