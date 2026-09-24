"""Data models and serialization structures for ShadowBoard L2 Observation Sidecar."""

import hashlib
import json
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TrafficDirection(str, Enum):
    EGRESS = "EGRESS"
    INGRESS = "INGRESS"


class NetworkObservationEvent(BaseModel):
    """An independently captured HTTP request/response event recorded by the sidecar proxy."""
    event_id: str = Field(default_factory=lambda: f"net_obs_{uuid.uuid4().hex[:12]}")
    session_id: str = "default"
    timestamp_utc: float = Field(default_factory=time.time)
    direction: TrafficDirection = TrafficDirection.EGRESS
    method: str = "GET"
    url: str
    host: str = ""
    path: str = "/"
    query_params: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    request_json: Optional[Any] = None
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None
    response_json: Optional[Any] = None
    payload_sha256: str = ""
    source: str = "proxy_observed"
    truth_level: str = "L2_PROXY_OBSERVED"

    def model_post_init(self, __context: Any) -> None:
        if not self.payload_sha256:
            content = f"{self.method}:{self.url}:{self.request_body or ''}:{self.status_code}:{self.response_body or ''}"
            self.payload_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

    def to_canonical_execution_event(self) -> Dict[str, Any]:
        """Convert raw network observation into ShadowBoard canonical execution event format."""
        # Extract potential tenant arguments from query params or request json
        args: Dict[str, Any] = {}
        args.update(self.query_params)
        if isinstance(self.request_json, dict):
            args.update(self.request_json)

        # Result data
        result: Dict[str, Any] = {
            "status_code": self.status_code,
            "success": bool(self.status_code and 200 <= self.status_code < 300),
        }
        if isinstance(self.response_json, dict):
            result.update(self.response_json)
        elif self.response_body:
            result["raw_body"] = self.response_body[:500]

        return {
            "event_type": "proxy_network_call",
            "source": "proxy_observed",
            "timestamp": self.timestamp_utc,
            "event_data": {
                "name": f"http_{self.method.lower()}",
                "method": self.method,
                "url": self.url,
                "host": self.host,
                "path": self.path,
                "arguments": args,
                "query_params": self.query_params,
                "result": result,
                "status_code": self.status_code,
                "direction": self.direction.value,
                "payload_sha256": self.payload_sha256,
                "session_id": self.session_id,
            },
        }


class SidecarSessionSummary(BaseModel):
    """Statistical and cryptographic summary of a sidecar observation session."""
    session_id: str
    total_events: int
    egress_calls: int
    ingress_calls: int
    hosts_contacted: List[str]
    linear_chain_hash: str
    merkle_root: str
    start_time_utc: float
    end_time_utc: float
