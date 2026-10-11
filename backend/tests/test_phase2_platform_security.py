"""Regression Tests for Stage 2 Platform Hardening (AUDIT.md A-07 to A-11).

Verifies:
1. A-07: Admin authentication is decided strictly by SHADOWBOARD_ADMIN_KEY and explicit test environment variables, never by sys.modules sniffing.
2. A-08: SSRF protection implements pin-and-connect, preventing DNS-rebinding TOCTOU gaps.
3. A-09: ErrorHandlingMiddleware returns structured JSONResponse and never raises into the ASGI layer.
4. A-11: Content-Security-Policy connect-src is built dynamically from configured CORS origins, banning wildcards.
"""

import os
import socket
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from app.core.middleware import (
    AdminAuthMiddleware,
    ErrorHandlingMiddleware,
    ProductionHeadersMiddleware,
    is_test_environment,
)
from app.core.config import settings
from app.core.ssrf import (
    PinAndValidateNetworkBackend,
    SSRFSafeTransport,
    SSRFValidationError,
    is_ip_blocked,
)


def test_a07_auth_not_bypassed_by_sys_modules():
    """A-07: Presence of pytest in sys.modules must not bypass admin auth when APP_ENV != 'test'."""
    with patch.dict(os.environ, {"APP_ENV": "production", "TESTING": ""}, clear=False):
        # Even though pytest is running this test, is_test_environment must return False
        assert is_test_environment() is False


def test_a07_admin_auth_fails_closed_in_production_without_key(monkeypatch):
    """A-07: In production without an admin key, /api must fail closed with 503."""
    app = FastAPI()
    app.add_middleware(AdminAuthMiddleware)

    @app.get("/api/test-route")
    async def protected():
        return {"status": "ok"}

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("SHADOWBOARD_ADMIN_KEY", raising=False)
    monkeypatch.delenv("SHADOWBOARD_API_KEY", raising=False)
    monkeypatch.setattr(settings, "SHADOWBOARD_ADMIN_KEY", None)
    monkeypatch.setattr(settings, "SHADOWBOARD_API_KEY", None)

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test-route")
    assert resp.status_code == 503
    assert "fail-closed" in resp.json()["detail"].lower()


def test_a08_ssrf_pin_and_connect_blocks_metadata():
    """A-08: PinAndValidateNetworkBackend blocks cloud metadata IP at connection time."""
    backend = PinAndValidateNetworkBackend(allow_local=False)

    with pytest.raises(SSRFValidationError, match="cloud metadata"):
        # Simulate connecting to cloud metadata
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]):
            import asyncio
            asyncio.run(backend.connect_tcp("metadata.google.internal", 80))


def test_a08_ssrf_pin_and_connect_blocks_loopback_unless_allowed():
    """A-08: PinAndValidateNetworkBackend blocks loopback IP when allow_local=False."""
    backend = PinAndValidateNetworkBackend(allow_local=False)

    with pytest.raises(SSRFValidationError, match="Loopback"):
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8080))]):
            import asyncio
            asyncio.run(backend.connect_tcp("malicious-rebind.internal", 8080))


def test_a09_error_handling_middleware_returns_json_response():
    """A-09: ErrorHandlingMiddleware catches HTTPExceptions and generic Exceptions, returning JSONResponse."""
    app = FastAPI()
    app.add_middleware(ErrorHandlingMiddleware)

    @app.get("/raise-http-404")
    async def raise_http():
        raise HTTPException(status_code=404, detail="Target entity not found")

    @app.get("/raise-unhandled")
    async def raise_unhandled():
        raise RuntimeError("Database connection suddenly dropped")

    client = TestClient(app, raise_server_exceptions=False)

    # 1. HTTPException produces proper JSON
    resp_404 = client.get("/raise-http-404")
    assert resp_404.status_code == 404
    assert resp_404.json() == {"detail": "Target entity not found"}

    # 2. Unhandled Exception produces 500 JSON without crashing ASGI server
    resp_500 = client.get("/raise-unhandled")
    assert resp_500.status_code == 500
    assert resp_500.json() == {"detail": "Internal server error"}


def test_a11_csp_header_restricts_connect_src():
    """A-11: Content-Security-Policy connect-src must not contain wildcard localhost ports."""
    app = FastAPI()
    app.add_middleware(ProductionHeadersMiddleware)

    @app.get("/test-csp")
    async def endpoint():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/test-csp")
    assert resp.status_code == 200

    csp = resp.headers.get("Content-Security-Policy", "")
    assert csp != ""
    # Must not contain hardcoded wildcard localhost
    assert "http://localhost:*" not in csp
    assert "http://127.0.0.1:*" not in csp
    # Must contain 'self'
    assert "connect-src 'self'" in csp
