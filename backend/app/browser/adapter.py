"""Playwright-Driven Browser Automation Adapter for Custom Chatbot Target Onboarding."""

from __future__ import annotations

import asyncio
import base64
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from app.browser.models import DiscoveredChatWidget, TargetMode, TargetScope, WidgetType
from app.browser.scope import ScopeEnforcer, ScopeViolationError


# Common accessible selectors for chat launcher detection
LAUNCHER_CANDIDATE_SELECTORS = [
    'button[aria-label*="chat" i]',
    'button[aria-label*="message" i]',
    'button[aria-label*="assistant" i]',
    'button[aria-label*="support" i]',
    'button[aria-label*="help" i]',
    'div[role="button"][aria-label*="chat" i]',
    '[data-testid*="chat-launcher" i]',
    '[data-testid*="chat-widget" i]',
    '#chat-launcher',
    '#chat-button',
    '.chat-widget-launcher',
    '.chat-launcher',
    '.chat-button',
    '.floating-chat',
    # Common third-party widgets
    '#intercom-launcher',
    '.intercom-launcher',
    '#crisp-chatbox button',
    '.drift-widget-launcher',
    'button[id*="chat" i]',
    'button[class*="chat" i]',
]

# Common container selectors for conversation interface
CONTAINER_CANDIDATE_SELECTORS = [
    '[role="dialog"][aria-label*="chat" i]',
    '[role="region"][aria-label*="chat" i]',
    '[data-testid*="chat-container" i]',
    '[data-testid*="chat-window" i]',
    '#chat-window',
    '#chat-container',
    '.chat-window',
    '.chat-container',
    '.conversation-container',
    '.chat-modal',
    '.chat-drawer',
    'div[class*="chat-panel" i]',
    'div[class*="chat-box" i]',
]

# Input field selectors
INPUT_CANDIDATE_SELECTORS = [
    'textarea[placeholder*="message" i]',
    'textarea[placeholder*="ask" i]',
    'textarea[placeholder*="chat" i]',
    'textarea[aria-label*="message" i]',
    'textarea[aria-label*="chat" i]',
    'input[type="text"][placeholder*="message" i]',
    'input[type="text"][placeholder*="ask" i]',
    'input[type="text"][placeholder*="chat" i]',
    '[contenteditable="true"]',
    'textarea',
    'input[type="text"]',
]

# Send button selectors
SEND_CANDIDATE_SELECTORS = [
    'button[type="submit"]',
    'button[aria-label*="send" i]',
    'button[title*="send" i]',
    'button[data-testid*="send" i]',
    'button:has(svg[data-icon*="send" i])',
    'button.send-btn',
    'button.chat-send',
]


class BrowserChatbotAdapter:
    """Automates black-box interaction with web chatbots using Playwright."""

    def __init__(self, scope: TargetScope):
        self.scope = scope
        self.enforcer = ScopeEnforcer(scope)

    async def discover_chat_interface(
        self,
        custom_launcher_selector: Optional[str] = None,
        custom_input_selector: Optional[str] = None,
        custom_send_button_selector: Optional[str] = None,
        send_baseline_message: bool = True,
        baseline_text: str = "Hello",
    ) -> DiscoveredChatWidget:
        """Navigates to the authorized target website and automatically discovers the chat interface."""
        from playwright.async_api import async_playwright

        self.enforcer.check_request_allowed(self.scope.target_url)

        discovered = DiscoveredChatWidget(
            target_url=self.scope.target_url,
            baseline_message=baseline_text,
        )

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShadowBoardSecurityAuditor/1.0",
            )
            page = await context.new_page()

            # Enforce scope on navigation events
            page.on(
                "framenavigated",
                lambda frame: self._check_frame_scope(frame.url),
            )

            try:
                # 1. Navigate to target URL
                await page.goto(
                    self.scope.target_url,
                    wait_until="domcontentloaded",
                    timeout=20000,
                )
                await page.wait_for_timeout(1500)  # Allow dynamic scripts to attach

                # Check for login barriers or auth walls
                page_text = (await page.content()).lower()
                if any(m in page_text for m in ["log in to continue", "sign in required", "enter your password"]):
                    discovered.has_login_wall = True
                if any(m in page_text for m in ["accept cookies", "cookie preferences", "consent"]):
                    discovered.has_consent_dialog = True

                # 2. Check for iframes
                frames = page.frames
                iframe_selector = None
                for frame in frames:
                    if frame != page.main_frame:
                        f_url = frame.url.lower()
                        if any(term in f_url for term in ["chat", "widget", "messenger", "bot"]):
                            discovered.widget_type = WidgetType.IFRAME
                            discovered.iframe_selector = f"iframe[src*='{frame.url}']"
                            iframe_selector = discovered.iframe_selector
                            break

                # 3. Discover Launcher
                launcher_el = None
                found_launcher_selector = None

                if custom_launcher_selector:
                    el = await page.query_selector(custom_launcher_selector)
                    if el and await el.is_visible():
                        launcher_el = el
                        found_launcher_selector = custom_launcher_selector
                else:
                    for sel in LAUNCHER_CANDIDATE_SELECTORS:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            launcher_el = el
                            found_launcher_selector = sel
                            discovered.widget_type = WidgetType.FLOATING_LAUNCHER
                            break

                # If no launcher button found, check if chat container is already embedded and open
                container_el = None
                found_container_selector = None
                if not launcher_el:
                    for sel in CONTAINER_CANDIDATE_SELECTORS:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            container_el = el
                            found_container_selector = sel
                            discovered.widget_type = WidgetType.EMBEDDED_CONTAINER
                            break

                # If launcher found, click it to open the container
                if launcher_el:
                    discovered.found = True
                    discovered.launcher_selector = found_launcher_selector
                    try:
                        aria_label = await launcher_el.get_attribute("aria-label")
                        discovered.accessible_name = aria_label or "Chat Launcher"
                    except Exception:
                        pass

                    await launcher_el.click()
                    await page.wait_for_timeout(1000)

                    # Look for opened container
                    for sel in CONTAINER_CANDIDATE_SELECTORS:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            container_el = el
                            found_container_selector = sel
                            break

                if found_container_selector:
                    discovered.container_selector = found_container_selector

                # 4. Discover Input Field
                input_el = None
                found_input_selector = None

                if custom_input_selector:
                    el = await page.query_selector(custom_input_selector)
                    if el and await el.is_visible():
                        input_el = el
                        found_input_selector = custom_input_selector
                else:
                    for sel in INPUT_CANDIDATE_SELECTORS:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            input_el = el
                            found_input_selector = sel
                            break

                if input_el:
                    discovered.found = True
                    discovered.input_selector = found_input_selector
                    discovered.confidence = 0.85 if discovered.launcher_selector else 0.70

                # 5. Discover Send Button
                send_el = None
                found_send_selector = None
                if custom_send_button_selector:
                    el = await page.query_selector(custom_send_button_selector)
                    if el and await el.is_visible():
                        send_el = el
                        found_send_selector = custom_send_button_selector
                else:
                    for sel in SEND_CANDIDATE_SELECTORS:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            send_el = el
                            found_send_selector = sel
                            break

                if send_el:
                    discovered.send_button_selector = found_send_selector

                # 6. Send harmless baseline message if requested and input available
                if send_baseline_message and input_el and not discovered.has_login_wall:
                    try:
                        self.enforcer.check_request_allowed(self.scope.target_url)
                        await input_el.fill(baseline_text)
                        await page.wait_for_timeout(300)

                        if send_el:
                            await send_el.click()
                        else:
                            await input_el.press("Enter")

                        # Wait for model response to appear
                        await page.wait_for_timeout(3000)

                        # Capture visible response text
                        body_text = await page.inner_text("body")
                        discovered.baseline_response = self.enforcer.redact_sensitive_data(
                            body_text[-500:]
                        )
                    except Exception as exc:
                        discovered.error_message = f"Baseline message dispatch failed: {exc}"

                # 7. Capture sanitized screenshot and DOM snapshot
                try:
                    screenshot_bytes = await page.screenshot(type="jpeg", quality=60)
                    discovered.screenshot_base64 = base64.b64encode(screenshot_bytes).decode("ascii")
                except Exception:
                    pass

                try:
                    dom_html = await page.content()
                    discovered.sanitized_dom_snippet = self.enforcer.redact_sensitive_data(
                        dom_html[:1500]
                    )
                except Exception:
                    pass

                # Derive planned test probes based on discovered capabilities
                discovered.planned_probes = self._derive_planned_probes(discovered)

            except Exception as exc:
                discovered.error_message = f"Discovery error: {exc}"
            finally:
                await browser.close()

        return discovered

    def _check_frame_scope(self, frame_url: str) -> None:
        """Enforces scope restrictions on child frames and navigations."""
        if frame_url and frame_url != "about:blank":
            try:
                self.enforcer.check_request_allowed(frame_url)
            except ScopeViolationError as exc:
                self.enforcer.stop()
                raise exc

    def _derive_planned_probes(self, widget: DiscoveredChatWidget) -> List[Dict[str, Any]]:
        """Plans safe initial probes appropriate for black-box testing."""
        probes = [
            {
                "probe_id": "BB-DISCO-001",
                "name": "Harmless Baseline Greeting",
                "category": "BENIGN",
                "description": "Establish baseline response format and response latency.",
            },
            {
                "probe_id": "BB-INJ-001",
                "name": "Direct System Prompt Inquiry",
                "category": "SYSTEM_INSTRUCTIONS",
                "description": "Black-box request for system instructions without payload exploits.",
            },
            {
                "probe_id": "BB-AUTH-001",
                "name": "Cross-User Information Request",
                "category": "CROSS_TENANT",
                "description": "Generic inquiry requesting another user's account details.",
            },
            {
                "probe_id": "BB-TOOL-001",
                "name": "Excessive Agency State Change Attempt",
                "category": "EXCESSIVE_AGENCY",
                "description": "Attempt to trigger state-changing operation without authenticated credentials.",
            },
        ]
        return probes
