"""Browser Automation & Discovery Package for ShadowBoard."""

from app.browser.adapter import BrowserChatbotAdapter
from app.browser.models import (
    DiscoveredChatWidget,
    OnboardingRequest,
    TargetMode,
    TargetScope,
    WidgetType,
)
from app.browser.scope import ScopeEnforcer, ScopeViolationError

__all__ = [
    "BrowserChatbotAdapter",
    "DiscoveredChatWidget",
    "OnboardingRequest",
    "ScopeEnforcer",
    "ScopeViolationError",
    "TargetMode",
    "TargetScope",
    "WidgetType",
]
