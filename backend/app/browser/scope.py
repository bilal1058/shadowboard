"""Scope Enforcement & Operational Safety Controller for Target Assessments."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from app.browser.models import TargetScope
from app.core.ssrf import SSRFValidationError, validate_target_url


class ScopeViolationError(Exception):
    """Raised when an operation attempts to exceed the authorized testing scope."""
    pass


class ScopeEnforcer:
    """Enforces target boundaries, rate limits, budgets, and safety stops."""

    def __init__(self, scope: TargetScope):
        if not scope.operator_authorized:
            raise ScopeViolationError(
                "Assessment refused: Operator has not confirmed ownership or explicit authorization."
            )
        self.scope = scope
        self._start_time = time.time()
        self._request_timestamps: List[float] = []
        self._total_requests = 0
        self._is_stopped = False

        # Pre-validate target URL using SSRF protections
        import os
        is_test_env = os.getenv("APP_ENV") == "test" or os.getenv("TESTING") == "1"
        validate_target_url(scope.target_url, allow_local=is_test_env)

    def stop(self) -> None:
        """Immediate emergency stop signal."""
        self._is_stopped = True

    @property
    def is_stopped(self) -> bool:
        return self._is_stopped

    def check_request_allowed(self, target_url: str, is_state_changing: bool = False) -> None:
        """Asserts that an outbound request is permissible under the active scope."""
        if self._is_stopped:
            raise ScopeViolationError("Testing halted: Operator triggered immediate emergency stop.")

        now = time.time()

        # 1. Test Duration
        elapsed = now - self._start_time
        if elapsed > self.scope.max_test_duration_sec:
            raise ScopeViolationError(
                f"Scope limit exceeded: Test duration {elapsed:.1f}s exceeded maximum "
                f"{self.scope.max_test_duration_sec}s."
            )

        # 2. Total Request Budget
        if self._total_requests >= self.scope.max_total_requests:
            raise ScopeViolationError(
                f"Scope limit exceeded: Total request budget of {self.scope.max_total_requests} reached."
            )

        # 3. State-changing action guard
        if is_state_changing and self.scope.disallow_state_changing_actions:
            raise ScopeViolationError(
                "Scope restriction: State-changing actions are prohibited in this assessment."
            )

        # 4. Domain & Origin Scope
        if not self.scope.validate_url_in_scope(target_url):
            raise ScopeViolationError(
                f"Out of scope navigation blocked: URL '{target_url}' is not in allowed scope "
                f"for target '{self.scope.target_url}'."
            )

        # 5. Rate Limiting (sliding window per second)
        cutoff = now - 1.0
        self._request_timestamps = [t for t in self._request_timestamps if t > cutoff]
        if len(self._request_timestamps) >= self.scope.max_request_rate_per_sec:
            # Throttle
            sleep_needed = 1.0 - (now - self._request_timestamps[0])
            if sleep_needed > 0:
                time.sleep(sleep_needed)

        self._request_timestamps.append(time.time())
        self._total_requests += 1

    @staticmethod
    def redact_sensitive_data(text: str) -> str:
        """Sanitizes text, DOM snapshots, and headers to prevent storing credentials in plaintext."""
        if not text:
            return ""
        # Redact bearer tokens, API keys, passwords, and session cookies
        redacted = re.sub(r'(bearer\s+)[A-Za-z0-9_\-\.]{12,}', r'\1[REDACTED_TOKEN]', text, flags=re.IGNORECASE)
        redacted = re.sub(r'((?:password|passwd|secret|api_key|token)[\s=:"\']+)[\w\-\.]{8,}', r'\1[REDACTED_SECRET]', redacted, flags=re.IGNORECASE)
        redacted = re.sub(r'(cookie:\s*)[^\r\n]+', r'\1[REDACTED_COOKIES]', redacted, flags=re.IGNORECASE)
        return redacted
