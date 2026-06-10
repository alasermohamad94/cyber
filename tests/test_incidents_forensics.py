"""Tests for incident management, case management, audit log hash-chaining,
the event replay engine, and the advanced query engine."""

import os
import tempfile
import time

import pytest

from storage.persistence import SecurityStore


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


def _make_event(store, event_id, target_entity="host-1", severity="high", event_type="port_scan", source_ip="10.0.0.1"):
    store.save_security_event(
        {
            "event_id": event_id,
            "timestamp": time.time(),
            "event_type": event_type,
            "severity": severity,
            "source_ip": source_ip,
            "target_entity": target_entity,
            "description": "test event",
            "action_taken": "alert",
            "status": "active",
        }
    )


# ------------------------------------------------------------------
# 1. Incident database schema / lifecycle
# ------------------------------------------------------------------

def test_incident_lifecycle(temp_store):
    _make_event(temp_store, "evt_1")
    incident = temp_store.create_incident(
        title="Port scan detected", description="desc", severity="high", event_ids=["evt_1"]
    )
    assert incident["status"] == "open"
    assert incident["event_ids"] == ["evt_1"]

    fetched = temp_store.get_incident(incident["incident_id"])
    assert fetched["title"] == "Port scan detected"

    updated = temp_store.update_incident(incident["incident_id"], status="investigating", assigned_to="analyst")
    assert updated["status"] == "investigating"
    assert updated["assigned_to"] == "analyst"

    with pytest.raises(ValueError):
        temp_store.update_incident(incident["incident_id"], status="not_a_status")


def test_incident_event_linking(temp_store):
    _make_event(temp_store, "evt_a")
    _make_event(temp_store, "evt_b")
    incident = temp_store.create_incident(title="Brute force", severity="critical", event_ids=["evt_a"])
    temp_store.link_event_to_incident(incident["incident_id"], "evt_b")
    events = temp_store.list_incident_events(incident["incident_id"])
    assert {e["event_id"] for e in events} == {"evt_a", "evt_b"}


def test_list_incidents_filters(temp_store):
    temp_store.create_incident(title="A", severity="low")
    inc2 = temp_store.create_incident(title="B", severity="critical")
    temp_store.update_incident(inc2["incident_id"], status="resolved")

    open_incidents = temp_store.list_incidents(status="open")
    assert all(i["status"] == "open" for i in open_incidents)
    resolved = temp_store.list_incidents(status="resolved")
    assert len(resolved) == 1
    assert resolved[0]["incident_id"] == inc2["incident_id"]


# ------------------------------------------------------------------
# 2. Case management
# ------------------------------------------------------------------

def test_case_management(temp_store):
    inc1 = temp_store.create_incident(title="Recon", severity="medium")
    inc2 = temp_store.create_incident(title="Lateral movement", severity="high")

    case = temp_store.create_case(title="APT campaign", incident_ids=[inc1["incident_id"]])
    assert case["incident_ids"] == [inc1["incident_id"]]

    temp_store.link_incident_to_case(case["case_id"], inc2["incident_id"])
    case = temp_store.get_case(case["case_id"])
    assert set(case["incident_ids"]) == {inc1["incident_id"], inc2["incident_id"]}

    # linking an incident to a case should set case_id on the incident too
    linked_incident = temp_store.get_incident(inc2["incident_id"])
    assert linked_incident["case_id"] == case["case_id"]

    updated = temp_store.update_case(case["case_id"], status="closed")
    assert updated["status"] == "closed"

    with pytest.raises(ValueError):
        temp_store.update_case(case["case_id"], status="bogus")


# ------------------------------------------------------------------
# 3. Immutable audit logs (hash-chaining)
# ------------------------------------------------------------------

def test_audit_log_chain_valid(temp_store):
    temp_store.append_audit_log("admin", "ip_blocked", {"ip_address": "1.2.3.4"})
    temp_store.append_audit_log("admin", "incident_created", {"incident_id": "inc_1"})
    temp_store.append_audit_log("analyst", "incident_updated", {"incident_id": "inc_1", "status": "resolved"})

    logs = temp_store.list_audit_logs()
    assert len(logs) == 3

    result = temp_store.verify_audit_chain()
    assert result["valid"] is True
    assert result["total"] == 3
    assert result["broken_at"] is None


def test_audit_log_chain_tamper_detection(temp_store):
    temp_store.append_audit_log("admin", "ip_blocked", {"ip_address": "1.2.3.4"})
    temp_store.append_audit_log("admin", "incident_created", {"incident_id": "inc_1"})

    # Tamper with the first record's details directly in the database.
    conn = temp_store._connect()
    try:
        conn.execute("UPDATE audit_logs SET details = ? WHERE log_id = 1", ('{"ip_address": "9.9.9.9"}',))
        conn.commit()
    finally:
        conn.close()

    result = temp_store.verify_audit_chain()
    assert result["valid"] is False
    assert result["broken_at"] == 1


# ------------------------------------------------------------------
# 4. Event replay engine
# ------------------------------------------------------------------

def test_event_replay_ordering(temp_store):
    _make_event(temp_store, "evt_1", target_entity="host-x")
    time.sleep(0.01)
    _make_event(temp_store, "evt_2", target_entity="host-x")
    time.sleep(0.01)
    _make_event(temp_store, "evt_3", target_entity="other-host")

    replay = temp_store.replay_events(target_entity="host-x")
    assert [e["event_id"] for e in replay] == ["evt_1", "evt_2"]
    # ascending order (oldest first) for step-by-step replay
    assert replay[0]["timestamp"] <= replay[1]["timestamp"]


def test_event_replay_time_window(temp_store):
    _make_event(temp_store, "evt_old", target_entity="host-y")
    start = time.time()
    time.sleep(0.01)
    _make_event(temp_store, "evt_new", target_entity="host-y")

    replay = temp_store.replay_events(target_entity="host-y", start_ts=start)
    assert [e["event_id"] for e in replay] == ["evt_new"]


# ------------------------------------------------------------------
# 5. Advanced query engine
# ------------------------------------------------------------------

def test_query_engine_and_logic(temp_store):
    _make_event(temp_store, "evt_critical", severity="critical", event_type="exfiltration", source_ip="1.1.1.1")
    _make_event(temp_store, "evt_high", severity="high", event_type="port_scan", source_ip="2.2.2.2")

    results = temp_store.query_events(
        filters=[
            {"field": "severity", "op": "eq", "value": "critical"},
            {"field": "event_type", "op": "eq", "value": "exfiltration"},
        ],
        logic="AND",
    )
    assert len(results) == 1
    assert results[0]["event_id"] == "evt_critical"


def test_query_engine_or_logic_and_in(temp_store):
    _make_event(temp_store, "evt_a", severity="low")
    _make_event(temp_store, "evt_b", severity="medium")
    _make_event(temp_store, "evt_c", severity="critical")

    results = temp_store.query_events(
        filters=[{"field": "severity", "op": "in", "value": ["low", "critical"]}],
        logic="OR",
    )
    ids = {r["event_id"] for r in results}
    assert ids == {"evt_a", "evt_c"}


def test_query_engine_contains(temp_store):
    _make_event(temp_store, "evt_x", source_ip="192.168.1.50")
    _make_event(temp_store, "evt_y", source_ip="10.0.0.5")

    results = temp_store.query_events(
        filters=[{"field": "source_ip", "op": "contains", "value": "192.168"}],
        logic="AND",
    )
    assert len(results) == 1
    assert results[0]["event_id"] == "evt_x"


def test_query_engine_ignores_unknown_fields(temp_store):
    _make_event(temp_store, "evt_z")
    # Unknown field/op should simply be ignored, not raise or break the query.
    results = temp_store.query_events(
        filters=[{"field": "not_a_real_field", "op": "eq", "value": "x"}],
        logic="AND",
    )
    assert len(results) == 1
