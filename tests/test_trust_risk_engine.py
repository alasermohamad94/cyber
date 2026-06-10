"""Tests for the trust-based risk scoring engine."""

import importlib
import os
import tempfile

import pytest

from storage.persistence import reset_store


@pytest.fixture
def trust_module():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ.pop("CDS_DATABASE_URL", None)
    os.environ["CDS_DB_PATH"] = path
    reset_store()

    import trust_system.trust_manager as trust_manager

    trust_manager = importlib.reload(trust_manager)
    trust_manager.reset_trust_manager()
    yield trust_manager

    reset_store()
    os.environ.pop("CDS_DB_PATH", None)
    trust_manager = importlib.reload(trust_manager)
    trust_manager.reset_trust_manager()
    try:
        os.remove(path)
    except OSError:
        pass


def test_risk_score_is_persisted_in_trust_record(trust_module):
    manager = trust_module.TrustManager()

    manager.update_trust_score("db_server_01", 82.0)
    record = manager.get_trust_record("db_server_01")

    assert record is not None
    assert 0.0 <= record["risk_score"] <= 100.0
    assert record["risk_level"] == "critical"
    assert record["risk_score"] >= 80.0


def test_repeated_suspicious_behavior_increases_risk_pressure(trust_module):
    manager = trust_module.TrustManager()

    manager.update_trust_score("entity_repeat", 45.0)
    first = manager.get_trust_record("entity_repeat")
    manager.update_trust_score("entity_repeat", 45.0)
    second = manager.get_trust_record("entity_repeat")

    assert first is not None
    assert second is not None
    assert second["risk_score"] > first["risk_score"]


def test_trust_statistics_include_average_risk_score(trust_module):
    manager = trust_module.TrustManager()

    manager.update_trust_score("host_low", 10.0)
    manager.update_trust_score("host_high", 70.0)
    stats = manager.get_trust_statistics()

    assert "average_risk_score" in stats
    assert stats["average_risk_score"] > 0.0
    assert stats["risk_distribution"]["low"] >= 1
    assert stats["risk_distribution"]["high"] + stats["risk_distribution"]["critical"] >= 1


def test_database_assets_receive_higher_risk_for_same_behavior(trust_module):
    manager = trust_module.TrustManager()

    manager.update_trust_score(
        "user_workstation_01",
        35.0,
        asset_context={"asset_type": "employee_device"},
    )
    workstation = manager.get_trust_record("user_workstation_01")

    manager.update_trust_score(
        "db_server_01",
        35.0,
        asset_context={"asset_type": "database_server"},
    )
    database = manager.get_trust_record("db_server_01")

    assert workstation is not None
    assert database is not None
    assert workstation["asset_criticality"] == 1.0
    assert database["asset_criticality"] == 5.0
    assert database["risk_score"] > workstation["risk_score"]
    assert database["risk_level"] in {"high", "critical"}
