"""Data models for Browser Chatbot Automation, Target Scope, and Discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetMode(str, Enum):
    BLACK_BOX = "BLACK_BOX"
    AUTHENTICATED_BLACK_BOX = "AUTHENTICATED_BLACK_BOX"
    INSTRUMENTED = "INSTRUMENTED"


class WidgetType(str, Enum):
    FLOATING_LAUNCHER = "FLOATING_LAUNCHER"
    EMBEDDED_CONTAINER = "EMBEDDED_CONTAINER"
    IFRAME = "IFRAME"
    MODAL_DRAWER = "MODAL_DRAWER"
    UNKNOWN = "UNKNOWN"


class TargetScope(BaseModel):
    """Enforceable operational scope restrictions for target assessments."""

    target_url: str
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_origins: List[str] = Field(default_factory=list)
    allow_redirects: bool = True
    max_redirects: int = 5
    max_request_rate_per_sec: float = 2.0
    max_test_duration_sec: int = 300
    max_total_requests: int = 50
    disallow_state_changing_actions: bool = True
    operator_authorized: bool = False
    authorized_by: str = ""
    notes: str = ""

    def validate_url_in_scope(self, url: str) -> bool:
        """Check if an arbitrary URL falls strictly within the configured scope."""
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False

        target_parsed = urlsplit(self.target_url)
        target_host = (target_parsed.hostname or "").lower()

        # The target's own hostname is always within scope
        if hostname == target_host or (target_host and hostname.endswith("." + target_host)):
            return True

        domain_match = any(
            hostname == d.lower() or hostname.endswith("." + d.lower())
            for d in self.allowed_domains
        )
        origin_host = f"{parsed.scheme}://{parsed.hostname}".lower()
        origin_full = f"{parsed.scheme}://{parsed.netloc}".lower()
        origin_match = any(
            origin_host == o.lower() or origin_full == o.lower() or origin_full.startswith(o.lower())
            for o in self.allowed_origins
        )
        return domain_match or origin_match


class DiscoveredChatWidget(BaseModel):
    """Observable interface attributes discovered from a target webpage."""

    target_url: str
    found: bool = False
    widget_type: WidgetType = WidgetType.UNKNOWN
    launcher_selector: Optional[str] = None
    container_selector: Optional[str] = None
    input_selector: Optional[str] = None
    send_button_selector: Optional[str] = None
    iframe_selector: Optional[str] = None
    accessible_name: Optional[str] = None
    has_login_wall: bool = False
    has_consent_dialog: bool = False
    confidence: float = 0.0
    discovery_method: str = "accessible_dom_heuristics"
    baseline_message: str = "Hello"
    baseline_response: Optional[str] = None
    screenshot_base64: Optional[str] = None
    sanitized_dom_snippet: Optional[str] = None
    error_message: Optional[str] = None
    planned_probes: List[Dict[str, Any]] = Field(default_factory=list)


class OnboardingRequest(BaseModel):
    """Request payload to onboard an authorized website or chatbot URL."""

    target_url: str
    operator_authorized: bool
    authorized_by: str
    target_mode: TargetMode = TargetMode.BLACK_BOX
    test_account_role: Optional[str] = None
    test_account_tenant_id: Optional[str] = None
    allowed_domains: List[str] = Field(default_factory=list)
    custom_launcher_selector: Optional[str] = None
    custom_input_selector: Optional[str] = None
    custom_send_button_selector: Optional[str] = None
    dry_run_only: bool = False
