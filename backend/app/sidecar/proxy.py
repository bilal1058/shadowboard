"""Observation Proxy and Network Interceptor for ShadowBoard L2 Substrate."""

import asyncio
import hashlib
import json
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import httpx

from app.evidence.bundler import EvidenceBundler, EvidencePackage, compute_event_chain_hash
from app.evidence.merkle import MerkleTree
from app.sidecar.models import NetworkObservationEvent, SidecarSessionSummary, TrafficDirection

logger = logging.getLogger(__name__)

SENSITIVE_HEADER_PATTERNS = re.compile(
    r"^(authorization|x-api-key|cookie|set-cookie|proxy-authorization|secret|token)",
    re.IGNORECASE,
)


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Sanitize sensitive credentials from captured request and response headers."""
    sanitized = {}
    for k, v in headers.items():
        if SENSITIVE_HEADER_PATTERNS.match(k):
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


class ObservationProxy:
    """Out-of-band network observation sidecar.
    
    Independently observes, records, and cryptographically signs network egress
    and ingress traffic to provide L2 PROXY_OBSERVED telemetry without relying
    on the target agent to report on itself.
    """

    def __init__(self, max_events_per_session: int = 1000):
        self.max_events = max_events_per_session
        self._sessions: Dict[str, List[NetworkObservationEvent]] = {}
        self._lock = threading.Lock()

    def start_session(self, session_id: str) -> None:
        """Initialize an isolated observation buffer for a scan or test session."""
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = []

    def clear_session(self, session_id: str) -> None:
        """Purge all recorded network events for the given session."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def record_event(
        self,
        session_id: str,
        method: str,
        url: str,
        direction: TrafficDirection = TrafficDirection.EGRESS,
        headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        status_code: Optional[int] = None,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Optional[str] = None,
        timestamp_utc: Optional[float] = None,
    ) -> NetworkObservationEvent:
        """Record an observed HTTP interaction in the specified session's buffer."""
        parsed = urlparse(url)
        raw_query = parse_qs(parsed.query)
        # Flatten single query parameter lists for easier matching
        query_params = {k: v[0] if len(v) == 1 else v for k, v in raw_query.items()}

        req_json = None
        if request_body:
            try:
                req_json = json.loads(request_body)
            except Exception:
                pass

        resp_json = None
        if response_body:
            try:
                resp_json = json.loads(response_body)
            except Exception:
                pass

        event = NetworkObservationEvent(
            session_id=session_id,
            timestamp_utc=timestamp_utc or time.time(),
            direction=direction,
            method=method.upper(),
            url=url,
            host=parsed.netloc,
            path=parsed.path,
            query_params=query_params,
            headers=sanitize_headers(headers or {}),
            request_body=request_body,
            request_json=req_json,
            status_code=status_code,
            response_headers=sanitize_headers(response_headers or {}),
            response_body=response_body,
            response_json=resp_json,
        )

        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = []
            if len(self._sessions[session_id]) < self.max_events:
                self._sessions[session_id].append(event)
            else:
                logger.warning("Sidecar buffer full for session %s, dropping event", session_id)

        return event

    async def forward_and_observe(
        self,
        session_id: str,
        method: str,
        target_url: str,
        direction: TrafficDirection = TrafficDirection.EGRESS,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
        timeout: float = 15.0,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Forward an HTTP request to the target destination and record the L2 observation."""
        req_body_str = content.decode("utf-8", errors="replace") if content else None
        t_start = time.time()

        # Clean outbound headers to avoid hop-by-hop issues
        fwd_headers = {k: v for k, v in (headers or {}).items() if k.lower() not in ("host", "content-length")}

        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                resp = await client.request(
                    method=method,
                    url=target_url,
                    headers=fwd_headers,
                    content=content,
                )
                status_code = resp.status_code
                resp_headers = dict(resp.headers)
                resp_bytes = resp.content
                resp_body_str = resp_bytes.decode("utf-8", errors="replace")
            except Exception as exc:
                status_code = 502
                resp_headers = {"content-type": "application/json"}
                resp_body_str = json.dumps({"error": "Bad Gateway", "details": str(exc)})
                resp_bytes = resp_body_str.encode("utf-8")

        self.record_event(
            session_id=session_id,
            method=method,
            url=target_url,
            direction=direction,
            headers=headers,
            request_body=req_body_str,
            status_code=status_code,
            response_headers=resp_headers,
            response_body=resp_body_str,
            timestamp_utc=t_start,
        )

        return status_code, resp_headers, resp_bytes

    def get_session_events(self, session_id: str) -> List[NetworkObservationEvent]:
        """Retrieve all raw recorded network events for a session."""
        with self._lock:
            return list(self._sessions.get(session_id, []))

    def to_canonical_execution_events(self, session_id: str) -> List[Dict[str, Any]]:
        """Map raw network observations to ShadowBoard canonical execution events."""
        events = self.get_session_events(session_id)
        return [e.to_canonical_execution_event() for e in events]

    def summarize_session(self, session_id: str) -> SidecarSessionSummary:
        """Produce an authenticated summary with Merkle tree and linear chain hashes."""
        events = self.get_session_events(session_id)
        canonical = [e.to_canonical_execution_event() for e in events]

        egress_count = sum(1 for e in events if e.direction == TrafficDirection.EGRESS)
        ingress_count = sum(1 for e in events if e.direction == TrafficDirection.INGRESS)
        hosts = sorted(list(set(e.host for e in events if e.host)))

        linear_hash = compute_event_chain_hash(canonical)
        merkle_root = MerkleTree(canonical).root

        t_start = events[0].timestamp_utc if events else time.time()
        t_end = events[-1].timestamp_utc if events else t_start

        return SidecarSessionSummary(
            session_id=session_id,
            total_events=len(events),
            egress_calls=egress_count,
            ingress_calls=ingress_count,
            hosts_contacted=hosts,
            linear_chain_hash=linear_hash,
            merkle_root=merkle_root,
            start_time_utc=t_start,
            end_time_utc=t_end,
        )

    def export_l2_evidence_package(
        self,
        session_id: str,
        scan_id: int,
        target_id: int,
        target_name: str,
        finding_id: str,
        rule_id: str,
        rule_name: str,
        severity: str,
        owasp_category: str,
        attack_prompts: List[str],
        strategies_used: List[str],
        response_text: str,
        violation_details: Dict[str, Any],
        remediation_text: str,
    ) -> EvidencePackage:
        """Create an independently verifiable L2 evidence package signed under PROXY_OBSERVED."""
        canonical_events = self.to_canonical_execution_events(session_id)
        return EvidenceBundler.create_package(
            scan_id=scan_id,
            target_id=target_id,
            target_name=target_name,
            finding_id=finding_id,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            owasp_category=owasp_category,
            attack_prompts=attack_prompts,
            strategies_used=strategies_used,
            response_text=response_text,
            execution_events=canonical_events,
            violation_details=violation_details,
            remediation_text=remediation_text,
            target_mode="PROXY_OBSERVED",
            substrate_truth_level="PROXY_OBSERVED",
        )


# Global singleton instance for embedded application usage
global_sidecar_proxy = ObservationProxy()


def get_sidecar_proxy() -> ObservationProxy:
    """Return the shared global observation proxy instance."""
    return global_sidecar_proxy
