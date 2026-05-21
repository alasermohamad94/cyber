"""Integration tests for auth, persistence, roles, and IP policy store."""

import os
import tempfile
import time

import pytest

from storage.persistence import SecurityStore
from security.auth import verify_credentials
from security.firewall import validate_ip
from security.roles import Role, role_has_permission


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


def test_flask_api_requires_auth():
    pytest.importorskip("flask")
    from web_dashboard.app import app

    client = app.test_client()
    assert client.get("/api/system-metrics").status_code == 401

    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["username"] = "admin"
        sess["role"] = Role.ADMIN.value
    assert client.get("/api/system-metrics").status_code == 200


def test_viewer_cannot_block_ip():
    pytest.importorskip("flask")
    from web_dashboard.app import app

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["username"] = "viewer"
        sess["role"] = Role.VIEWER.value
    resp = client.post(
        "/api/block-ip",
        json={"ip_address": "10.0.0.99"},
        content_type="application/json",
    )
    assert resp.status_code == 403


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
