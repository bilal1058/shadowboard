import os
import sys
import pytest
import asyncio
from unittest.mock import patch
from fastapi.testclient import TestClient
from main import app
from app.core.config import Settings
from app.core.ssrf import validate_target_url, safe_http_get_json, SSRFValidationError
from app.api.endpoints.scans import (
    active_scans,
    active_scans_lock,
    MAX_CONCURRENT_SCANS,
    sse_queues,
    cleanup_sse_scan,
    broadcast_sse_event,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoints_accessible_without_auth(client):
    """0.3 & 0.5: Health endpoints must respond 200 without requiring API keys."""
    resp1 = client.get("/health")
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "healthy"

    resp2 = client.get("/api/health")
    assert resp2.status_code == 200
    assert resp2.json()["status"] in ("healthy", "ok")


def test_admin_auth_middleware_with_configured_key(client):
    """0.5: Enforce fail-closed SHADOWBOARD_ADMIN_KEY with constant-time comparison."""
    test_key = "sb_admin_secret_9942a8b17c330f81d9e"
    old_env = os.environ.get("SHADOWBOARD_ADMIN_KEY")
    os.environ["SHADOWBOARD_ADMIN_KEY"] = test_key

    try:
        # 1. Missing auth credentials -> 401 Unauthorized
        resp_missing = client.get("/api/targets")
        assert resp_missing.status_code == 401
        assert "Missing" in resp_missing.json()["detail"]

        # 2. Invalid auth credentials -> 403 Forbidden
        resp_bad = client.get("/api/targets", headers={"Authorization": "Bearer bad_secret"})
        assert resp_bad.status_code == 403
        assert "Invalid" in resp_bad.json()["detail"]

        # 3. Valid Bearer auth -> 200 OK
        resp_good = client.get("/api/targets", headers={"Authorization": f"Bearer {test_key}"})
        assert resp_good.status_code == 200
        assert isinstance(resp_good.json(), list)

        # 4. Valid X-API-Key header -> 200 OK
        resp_good_x = client.get("/api/targets", headers={"X-API-Key": test_key})
        assert resp_good_x.status_code == 200

        # 5. Exempt route (/api/health) still works with no auth
        resp_health = client.get("/api/health")
        assert resp_health.status_code == 200

    finally:
        if old_env is not None:
            os.environ["SHADOWBOARD_ADMIN_KEY"] = old_env
        else:
            os.environ.pop("SHADOWBOARD_ADMIN_KEY", None)


def test_admin_auth_fail_closed_in_non_test_mode(client):
    """0.5: When key is unset in production, API must fail closed (503), not allow requests."""
    old_env = os.environ.pop("SHADOWBOARD_ADMIN_KEY", None)
    try:
        with patch("app.core.middleware.is_test_environment", return_value=False):
            resp = client.get("/api/targets")
            assert resp.status_code == 503
            assert "fail-closed" in resp.json()["detail"].lower()
    finally:
        if old_env is not None:
            os.environ["SHADOWBOARD_ADMIN_KEY"] = old_env


def test_cors_origin_parsing_bans_wildcard():
    """0.6: CORS origins must never allow wildcard '*'."""
    # Valid origin list
    s1 = Settings(CORS_ORIGINS="http://localhost:3000, http://127.0.0.1:8000")
    assert "http://localhost:3000" in s1.CORS_ORIGINS
    assert "http://127.0.0.1:8000" in s1.CORS_ORIGINS

    # Wildcard origin must raise ValidationError
    with pytest.raises(ValueError, match="strictly prohibited"):
        Settings(CORS_ORIGINS="*")

    with pytest.raises(ValueError, match="strictly prohibited"):
        Settings(CORS_ORIGINS="http://localhost:3000, *")


def test_ssrf_validation_blocks_illegal_schemes_and_ranges():
    """0.7: Target registration must block non-http(s), metadata, loopback, private IPs."""
    # Non-http schemes
    with pytest.raises(SSRFValidationError, match="Prohibited URL scheme"):
        validate_target_url("file:///etc/passwd")

    with pytest.raises(SSRFValidationError, match="Prohibited URL scheme"):
        validate_target_url("gopher://127.0.0.1:25/")

    with pytest.raises(SSRFValidationError, match="Prohibited URL scheme"):
        validate_target_url("ftp://192.168.1.1/")

    # Cloud metadata
    with pytest.raises(SSRFValidationError, match="cloud metadata"):
        validate_target_url("http://169.254.169.254/latest/meta-data/")

    # Private RFC 1918 / Loopback when allow_local is False
    with pytest.raises(SSRFValidationError, match="Loopback"):
        validate_target_url("http://127.0.0.1:8000/target-app", allow_local=False)

    with pytest.raises(SSRFValidationError, match="Loopback"):
        validate_target_url("http://localhost:8000/target-app", allow_local=False)

    # Local reference targets with allow_local=True succeed
    cleaned = validate_target_url("http://127.0.0.1:8000/target-app", allow_local=True)
    assert cleaned == "http://127.0.0.1:8000/target-app"


def test_target_api_endpoints_enforce_ssrf_blocking(client):
    """0.7: POST /api/targets and test-connection reject SSRF payloads with 400."""
    # Test-connection with metadata IP
    resp_tc = client.post("/api/targets/test-connection", json={"base_url": "http://169.254.169.254/latest"})
    assert resp_tc.status_code == 400
    assert "SSRF validation" in resp_tc.json()["detail"]

    # Target registration with private IP
    resp_create = client.post(
        "/api/targets",
        json={
            "name": "Malicious Private Target",
            "base_url": "http://10.0.0.5:8080/probe",
            "model_name": "qwen-flash",
            "target_type": "EXTERNAL_SUPPORT",
            "target_mode": "INSTRUMENTED",
            "capabilities": {"chat": True, "rag": False, "tools": False, "data_access": False, "tool_names": []},
        },
    )
    assert resp_create.status_code == 400
    assert "SSRF validation" in resp_create.json()["detail"]


@pytest.mark.asyncio
async def test_sse_lifecycle_bounded_and_cleaned():
    """0.8: SSE queues must be bounded and purged on cleanup without memory leak."""
    scan_id = 99999
    sse_queues[scan_id] = [asyncio.Queue(maxsize=2)]

    # Broadcast events
    await broadcast_sse_event(scan_id, "test_event", {"num": 1})
    await broadcast_sse_event(scan_id, "test_event", {"num": 2})
    # Exceeding bounded queue must drop oldest and not raise QueueFull
    await broadcast_sse_event(scan_id, "test_event", {"num": 3})

    assert scan_id in sse_queues
    q = sse_queues[scan_id][0]
    assert q.qsize() <= 2

    # Run cleanup
    await cleanup_sse_scan(scan_id, delay_seconds=0.01)

    # Scan entry must be purged from memory
    assert scan_id not in sse_queues


def test_scan_concurrency_limit_rejects_4th_scan(client):
    """0.9: Max 3 concurrent scans enforced; 4th scan rejected with 429."""
    # Seed 3 active scans into the concurrency tracking set
    dummy_scans = {88881, 88882, 88883}
    active_scans.update(dummy_scans)
    try:
        resp = client.post(
            "/api/scans",
            json={
                "target_id": 1,
                "scan_mode": "INSTRUMENTED",
                "mitigation_enabled": False,
            },
        )
        assert resp.status_code == 429
        assert "Concurrent scan limit reached" in resp.json()["detail"]
        assert resp.headers.get("Retry-After") == "5"
    finally:
        active_scans.difference_update(dummy_scans)

