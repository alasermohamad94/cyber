"""API-level tests for incidents, cases, and forensics endpoints."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from storage.persistence import reset_store


@pytest.fixture
def api_client():
    reset_store()
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ.pop("CDS_DATABASE_URL", None)
    os.environ["CDS_DB_PATH"] = path
    reset_store()

    from backend.main import app

    with TestClient(app) as client:
        yield client

    reset_store()
    os.environ.pop("CDS_DB_PATH", None)
    try:
        os.remove(path)
    except OSError:
        pass


def _login(client: TestClient, username: str, password: str):
    return client.post("/api/login", data={"username": username, "password": password})


def test_incident_crud_flow(api_client):
    _login(api_client, "admin", os.environ.get("CDS_ADMIN_PASSWORD", "changeme"))

    create = api_client.post(
        "/api/incidents",
        json={"title": "Suspicious login burst", "description": "many failed logins", "severity": "high"},
    )
    assert create.status_code == 200
    incident_id = create.json()["incident_id"]

    listing = api_client.get("/api/incidents")
    assert listing.status_code == 200
    assert listing.json()["count"] == 1

    update = api_client.patch(f"/api/incidents/{incident_id}", json={"status": "investigating"})
    assert update.status_code == 200
    assert update.json()["status"] == "investigating"

    bad_status = api_client.patch(f"/api/incidents/{incident_id}", json={"status": "nope"})
    assert bad_status.status_code == 400


def test_case_links_incident(api_client):
    _login(api_client, "admin", os.environ.get("CDS_ADMIN_PASSWORD", "changeme"))

    incident = api_client.post("/api/incidents", json={"title": "Exfil attempt", "severity": "critical"}).json()
    case = api_client.post("/api/cases", json={"title": "Campaign X", "incident_ids": [incident["incident_id"]]})
    assert case.status_code == 200
    case_id = case.json()["case_id"]

    fetched = api_client.get(f"/api/cases/{case_id}")
    assert fetched.status_code == 200
    assert fetched.json()["incident_ids"] == [incident["incident_id"]]


def test_viewer_cannot_write_incidents(api_client):
    _login(api_client, "viewer", os.environ.get("CDS_VIEWER_PASSWORD", "viewer123"))
    resp = api_client.post("/api/incidents", json={"title": "x", "severity": "low"})
    assert resp.status_code == 403
    # Viewer can still read
    assert api_client.get("/api/incidents").status_code == 200


def test_audit_log_and_verify(api_client):
    _login(api_client, "admin", os.environ.get("CDS_ADMIN_PASSWORD", "changeme"))

    api_client.post("/api/incidents", json={"title": "Test", "severity": "low"})

    logs = api_client.get("/api/audit-logs")
    assert logs.status_code == 200
    assert len(logs.json()["logs"]) >= 1

    verify = api_client.get("/api/audit-logs/verify")
    assert verify.status_code == 200
    assert verify.json()["valid"] is True


def test_forensics_replay_and_query(api_client):
    _login(api_client, "admin", os.environ.get("CDS_ADMIN_PASSWORD", "changeme"))

    block = api_client.post("/api/block-ip", json={"ip_address": "10.0.0.99", "reason": "test"})
    assert block.status_code == 200

    replay = api_client.get("/api/forensics/replay", params={"target_entity": "firewall"})
    assert replay.status_code == 200
    assert replay.json()["count"] >= 1

    query = api_client.post(
        "/api/forensics/query",
        json={"filters": [{"field": "event_type", "op": "eq", "value": "ip_blocked"}], "logic": "AND"},
    )
    assert query.status_code == 200
    assert query.json()["count"] >= 1


def test_forensics_requires_analyst_or_admin(api_client):
    _login(api_client, "viewer", os.environ.get("CDS_VIEWER_PASSWORD", "viewer123"))
    assert api_client.get("/api/forensics/replay").status_code == 403
    assert api_client.get("/api/audit-logs/verify").status_code == 403
