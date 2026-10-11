"""Comprehensive Test Suite for Custom Target Onboarding, Browser Automation & Scope Enforcement.

Verifies:
  - TargetScope & ScopeEnforcer rate limits, duration budgets, emergency stop, and redactions.
  - BrowserChatbotAdapter discovery of floating launchers, inputs, and send buttons using Playwright.
  - Onboarding REST API endpoints: discovery, templates, confirmation, and SSRF/authorization guards.
"""

import asyncio
import http.server
import socket
import threading
from typing import Generator
import pytest
from fastapi.testclient import TestClient

from app.browser.adapter import BrowserChatbotAdapter
from app.browser.models import OnboardingRequest, TargetMode, TargetScope, WidgetType
from app.browser.scope import ScopeEnforcer, ScopeViolationError
from main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test Fixture: Ephemeral HTML Server with Floating Chat Launcher
# ---------------------------------------------------------------------------

SAMPLE_CHAT_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>Enterprise Portal</title>
  <style>
    body { font-family: sans-serif; margin: 40px; }
    .floating-chat-btn {
      position: fixed;
      bottom: 24px;
      right: 24px;
      padding: 12px 20px;
      background: #2563eb;
      color: white;
      border: none;
      border-radius: 9999px;
      cursor: pointer;
      font-size: 16px;
    }
    #chat-box {
      display: none;
      position: fixed;
      bottom: 80px;
      right: 24px;
      width: 320px;
      height: 400px;
      background: white;
      border: 1px solid #ccc;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      border-radius: 8px;
      padding: 16px;
    }
    #messages { height: 280px; overflow-y: auto; border-bottom: 1px solid #eee; margin-bottom: 12px; }
  </style>
</head>
<body>
  <h1>Welcome to Enterprise Services</h1>
  <p>Support is available 24/7 via our automated assistant.</p>

  <button id="chat-button" class="floating-chat-btn" aria-label="Customer Support Chat" onclick="toggleChat()">
    💬 Chat with Assistant
  </button>

  <div id="chat-box" role="dialog" aria-label="Support Chat Window">
    <div id="messages">
      <div class="msg bot">Hello! How can I assist you with your enterprise account today?</div>
    </div>
    <div style="display: flex; gap: 8px;">
      <input type="text" id="chat-input" placeholder="Type your message..." style="flex: 1; padding: 8px;" />
      <button id="send-button" aria-label="Send message" onclick="sendMsg()" style="padding: 8px 12px;">Send</button>
    </div>
  </div>

  <script>
    function toggleChat() {
      var box = document.getElementById('chat-box');
      box.style.display = box.style.display === 'block' ? 'none' : 'block';
    }
    function sendMsg() {
      var input = document.getElementById('chat-input');
      var msgs = document.getElementById('messages');
      if (input.value.trim()) {
        var userDiv = document.createElement('div');
        userDiv.className = 'msg user';
        userDiv.textContent = input.value;
        msgs.appendChild(userDiv);
        input.value = '';
        setTimeout(function() {
          var botDiv = document.createElement('div');
          botDiv.className = 'msg bot';
          botDiv.textContent = 'I received your inquiry. A support representative will review your request shortly.';
          msgs.appendChild(botDiv);
        }, 300);
      }
    }
  </script>
</body>
</html>
"""


class MockChatServerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(SAMPLE_CHAT_HTML.encode("utf-8"))

    def log_message(self, format, *args):
        pass  # Suppress server access logs during tests


@pytest.fixture(scope="module")
def mock_chat_webpage() -> Generator[str, None, None]:
    """Spawns an ephemeral HTTP server serving SAMPLE_CHAT_HTML."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    server = http.server.HTTPServer(("127.0.0.1", port), MockChatServerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}/"
    yield url
    server.shutdown()
    server.server_close()


# =====================================================================
# 1. Target Scope & Safety Enforcer Tests
# =====================================================================

def test_scope_requires_explicit_operator_authorization():
    """Safety invariant: Target assessment fails-closed if operator_authorized is False."""
    scope = TargetScope(
        target_url="https://example.com/portal",
        operator_authorized=False,
    )
    with pytest.raises(ScopeViolationError, match="Operator has not confirmed ownership"):
        ScopeEnforcer(scope)


def test_scope_domain_and_origin_allowlist(monkeypatch):
    """Asserts that requests outside configured domain allowlist are rejected."""
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    scope = TargetScope(
        target_url="https://app.example.com/chat",
        allowed_domains=["app.example.com", "api.example.com"],
        operator_authorized=True,
        authorized_by="Lead Security Auditor",
    )
    enforcer = ScopeEnforcer(scope)

    # Allowed in scope
    enforcer.check_request_allowed("https://app.example.com/chat/messages")
    enforcer.check_request_allowed("https://api.example.com/v1/query")

    # Forbidden out-of-scope domain
    with pytest.raises(ScopeViolationError, match="Out of scope"):
        enforcer.check_request_allowed("https://malicious-thirdparty.com/exfiltrate")


def test_scope_enforcer_rate_limiting_and_budgets():
    """Enforcer throttles request rate and caps max request budget."""
    scope = TargetScope(
        target_url="https://example.com/chat",
        operator_authorized=True,
        authorized_by="Lead Security Auditor",
        max_total_requests=3,
        max_request_rate_per_sec=10.0,
    )
    enforcer = ScopeEnforcer(scope)

    enforcer.check_request_allowed("https://example.com/chat")
    enforcer.check_request_allowed("https://example.com/chat")
    enforcer.check_request_allowed("https://example.com/chat")

    # 4th request exceeds budget of 3
    with pytest.raises(ScopeViolationError, match="Total request budget"):
        enforcer.check_request_allowed("https://example.com/chat")


def test_scope_emergency_stop():
    """Emergency stop signal immediately halts further testing."""
    scope = TargetScope(
        target_url="https://example.com/chat",
        operator_authorized=True,
        authorized_by="Lead Security Auditor",
    )
    enforcer = ScopeEnforcer(scope)
    enforcer.check_request_allowed("https://example.com/chat")

    enforcer.stop()
    assert enforcer.is_stopped is True

    with pytest.raises(ScopeViolationError, match="emergency stop"):
        enforcer.check_request_allowed("https://example.com/chat")


def test_scope_sensitive_data_redaction():
    """Redacts passwords, tokens, and cookies from evidence text."""
    raw = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecrettoken123\n"
        "User credentials: password='VerySecretPassword123' and api_key=sk-12345678abcdefghij\n"
        "Cookie: session_id=xyz789; secure; HttpOnly"
    )
    sanitized = ScopeEnforcer.redact_sensitive_data(raw)
    assert "supersecrettoken123" not in sanitized
    assert "VerySecretPassword123" not in sanitized
    assert "sk-12345678abcdefghij" not in sanitized
    assert "xyz789" not in sanitized
    assert "[REDACTED_TOKEN]" in sanitized
    assert "[REDACTED_SECRET]" in sanitized
    assert "[REDACTED_COOKIES]" in sanitized


# =====================================================================
# 2. Onboarding REST API Endpoints Tests
# =====================================================================

def test_api_onboarding_templates():
    """GET /api/onboarding/templates returns supported testing modes and attack families."""
    resp = client.get("/api/onboarding/templates")
    assert resp.status_code == 200
    data = resp.json()
    assert "testing_modes" in data
    assert any(m["mode"] == "BLACK_BOX" for m in data["testing_modes"])
    assert any(m["mode"] == "AUTHENTICATED_BLACK_BOX" for m in data["testing_modes"])
    assert any(m["mode"] == "INSTRUMENTED" for m in data["testing_modes"])
    assert len(data["generic_attack_families"]) >= 5


def test_api_onboarding_rejects_unauthorized():
    """POST /api/onboarding/discover rejects requests without operator authorization."""
    req = {
        "target_url": "https://example.com/chat",
        "operator_authorized": False,
        "authorized_by": "",
    }
    resp = client.post("/api/onboarding/discover", json=req)
    assert resp.status_code == 400
    assert "Authorization Refusal" in resp.json()["detail"]


def test_api_onboarding_rejects_private_ssrf():
    """POST /api/onboarding/discover rejects private RFC1918 / cloud metadata targets."""
    req = {
        "target_url": "http://169.254.169.254/latest/meta-data",
        "operator_authorized": True,
        "authorized_by": "Security Officer",
    }
    resp = client.post("/api/onboarding/discover", json=req)
    assert resp.status_code == 400
    assert "Security Scope Violation" in resp.json()["detail"]


def test_api_onboarding_dry_run_preview():
    """POST /api/onboarding/discover in dry_run_only mode returns planned test preview."""
    req = {
        "target_url": "https://example.com/chat",
        "operator_authorized": True,
        "authorized_by": "Auditor Lead",
        "dry_run_only": True,
    }
    resp = client.post("/api/onboarding/discover", json=req)
    assert resp.status_code == 200
    data = resp.json()
    assert data["discovery_method"] == "dry_run_preview"
    assert len(data["planned_probes"]) > 0


def test_api_onboarding_confirm_profile():
    """POST /api/onboarding/confirm saves verified profile."""
    profile_req = {
        "target_url": "https://example.com/chat",
        "target_name": "ACME Customer Assistant",
        "target_mode": "BLACK_BOX",
        "operator_authorized": True,
        "authorized_by": "Auditor Lead",
        "launcher_selector": "#chat-button",
        "input_selector": "#chat-input",
        "send_button_selector": "#send-button",
        "scope_allowed_domains": ["example.com"],
        "planned_probes": [{"probe_id": "P-01"}],
    }
    resp = client.post("/api/onboarding/confirm", json=profile_req)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "CONFIRMED"
    assert data["target_profile"]["selectors"]["launcher"] == "#chat-button"
    target_id = data.get("target_id")
    if target_id:
        from app.db.session import DB_PATH
        import sqlite3
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            conn.commit()


# =====================================================================
# 3. Real Playwright Headless Browser Discovery Integration Test
# =====================================================================

@pytest.mark.asyncio
async def test_playwright_chat_widget_discovery_and_baseline(mock_chat_webpage: str):
    """Launches Playwright headless Chromium against mock webpage and verifies:
      - Floating launcher discovered via accessible name and attributes.
      - Launcher clicked to open container.
      - Text input and send button identified.
      - Harmless baseline probe sent and response captured.
      - Screenshot and sanitized DOM captured.
    """
    scope = TargetScope(
        target_url=mock_chat_webpage,
        operator_authorized=True,
        authorized_by="E2E Browser Tester",
        allowed_origins=["http://127.0.0.1"],
    )
    # Allow local ephemeral test port for test environment
    adapter = BrowserChatbotAdapter(scope=scope)

    discovered = await adapter.discover_chat_interface(
        send_baseline_message=True,
        baseline_text="Hello support",
    )

    assert discovered.found is True
    assert discovered.widget_type in (WidgetType.FLOATING_LAUNCHER, WidgetType.EMBEDDED_CONTAINER)
    assert discovered.launcher_selector is not None
    assert discovered.input_selector is not None
    assert discovered.send_button_selector is not None
    assert discovered.confidence >= 0.70
    assert discovered.accessible_name is not None
    assert discovered.has_login_wall is False

    # Screenshot and DOM snapshots captured
    assert discovered.screenshot_base64 is not None
    assert len(discovered.screenshot_base64) > 100
    assert discovered.sanitized_dom_snippet is not None

    # Baseline response captured
    assert discovered.baseline_response is not None
    assert len(discovered.planned_probes) >= 4
