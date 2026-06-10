"""Integration tests for auth, persistence, roles, and IP policy store."""

import importlib
import os
import tempfile
import time

import pytest

from storage.persistence import SecurityStore, reset_store, get_store
from security.auth import verify_credentials
from security.firewall import validate_ip
from security.config import get_user_directory
from security.roles import Role, permissions_for_role, role_has_permission


@pytest.fixture
def temp_store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = SecurityStore(db_path=path)
    yield store
    try:
        os.remove(path)
    except OSError:
        pass


def test_verify_credentials_roles():
    os.environ["CDS_ADMIN_USER"] = "tester"
    os.environ["CDS_ADMIN_PASSWORD"] = "secret"
    assert verify_credentials("tester", "secret") == Role.ADMIN.value
    assert verify_credentials("tester", "wrong") is None


def test_role_permissions():
    assert role_has_permission(Role.ADMIN.value, "ip:block")
    assert not role_has_permission(Role.VIEWER.value, "ip:block")
    assert role_has_permission(Role.ANALYST.value, "entity:analyze")


def test_ip_validation():
    assert validate_ip("192.168.1.1")
    assert not validate_ip("999.1.1.1")


def test_blocked_ip_persistence(temp_store):
    temp_store.save_blocked_ip("10.0.0.5", "test", firewall_applied=False)
    rows = temp_store.list_blocked_ips()
    assert len(rows) == 1
    assert rows[0]["ip_address"] == "10.0.0.5"
    assert temp_store.unblock_ip("10.0.0.5")
    assert temp_store.count_blocked_ips() == 0


def test_security_event_persistence(temp_store):
    ts = time.time()
    temp_store.save_security_event(
        {
            "event_id": "evt_test",
            "timestamp": ts,
            "event_type": "test",
            "severity": "high",
            "source_ip": "1.2.3.4",
            "target_entity": "host",
            "description": "unit test",
            "action_taken": "alert",
            "status": "active",
        }
    )
    events = temp_store.list_security_events()
    assert events[0]["event_id"] == "evt_test"
    assert temp_store.count_events_since(ts - 1, "high") >= 1


def test_viewer_permissions_list():
    perms = permissions_for_role(Role.VIEWER.value)
    assert "metrics:read" in perms
    assert "security:read" in perms
    assert "ip:block" not in perms
    assert "entity:analyze" not in perms
    assert "report:generate" not in perms


def test_analyst_permissions_list():
    perms = permissions_for_role(Role.ANALYST.value)
    assert "entity:analyze" in perms
    assert "report:generate" in perms
    assert "ip:block" not in perms


def test_duplicate_cds_usernames_rejected():
    os.environ["CDS_ADMIN_USER"] = "same"
    os.environ["CDS_ANALYST_USER"] = "same"
    os.environ["CDS_VIEWER_USER"] = "viewer"
    with pytest.raises(ValueError, match="Duplicate"):
        get_user_directory()
    os.environ.pop("CDS_ADMIN_USER", None)
    os.environ.pop("CDS_ANALYST_USER", None)


def test_ml_shadow_predict():
    from prediction.model_inference import shadow_predict

    result = shadow_predict({
        "entity_data": {
            "connection_rate": 0.9,
            "request_rate": 0.9,
            "failed_auth_count": 50,
            "total_auth_count": 55,
            "unique_ports": 0.8,
            "sensitive_access_count": 0.7,
        },
        "behavior_score": 85.0,
    })
    assert result["enabled"] is True
    assert "advisory_score" in result


def test_web_monitor_records_correlated_incident_event():
    pytest.importorskip("psutil")
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ.pop("CDS_DATABASE_URL", None)
    os.environ["CDS_DB_PATH"] = path
    reset_store()

    import backend.services.monitor as monitor_module

    monitor_module = importlib.reload(monitor_module)
    web_monitor = monitor_module.monitor

    try:
        web_monitor.analyze_entity(
            "scan_entity",
            {
                "source_ip": "198.51.100.55",
                "connection_rate": 0.85,
                "request_rate": 0.4,
                "unique_ports": 0.95,
                "unique_source_ips": 5,
                "target_host": "db-core-01",
                "scan_window_seconds": 120,
            },
        )
        web_monitor.analyze_entity(
            "auth_entity",
            {
                "source_ip": "198.51.100.55",
                "connection_rate": 0.2,
                "request_rate": 0.2,
                "failed_auth_count": 18,
                "total_auth_count": 20,
                "failed_auth_window_seconds": 120,
                "username": "admin",
                "unique_target_users": 1,
            },
        )

        events = get_store().list_security_events(10)

        assert any(
            event["event_type"] == "recon_to_initial_access" for event in events
        )
    finally:
        web_monitor.cpu_sampler._running = False
        reset_store()
        os.environ.pop("CDS_DB_PATH", None)
        try:
            os.remove(path)
        except OSError:
            pass
