"""Integration tests for FastAPI backend."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from security.roles import Role, permissions_for_role
from storage.persistence import SecurityStore, reset_store


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
    return client.post(
        "/api/login",
        data={"username": username, "password": password},
    )


def test_api_requires_auth(api_client):
    assert api_client.get("/api/system-metrics").status_code == 401


def test_admin_metrics(api_client):
    _login(api_client, "admin", os.environ.get("CDS_ADMIN_PASSWORD", "changeme"))
    assert api_client.get("/api/system-metrics").status_code == 200


def test_viewer_cannot_block_ip(api_client):
    _login(api_client, "viewer", os.environ.get("CDS_VIEWER_PASSWORD", "viewer123"))
    resp = api_client.post("/api/block-ip", json={"ip_address": "10.0.0.99"})
    assert resp.status_code == 403


def test_session_role_not_escalated(api_client):
    _login(api_client, "viewer", os.environ.get("CDS_VIEWER_PASSWORD", "viewer123"))
    data = api_client.get("/api/session-info").json()
    assert data["role"] == Role.VIEWER.value
    assert "ip:block" not in data["permissions"]


def test_login_assigns_viewer_role(api_client):
    _login(api_client, "viewer", os.environ.get("CDS_VIEWER_PASSWORD", "viewer123"))
    data = api_client.get("/api/session-info").json()
    assert data["role"] == Role.VIEWER.value
    assert set(data["permissions"]) == set(permissions_for_role(Role.VIEWER.value))


def test_health(api_client):
    assert api_client.get("/api/health").json()["status"] == "ok"
