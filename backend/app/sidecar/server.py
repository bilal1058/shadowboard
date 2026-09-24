"""Standalone ASGI Sidecar Server for ShadowBoard Out-of-Process Observation."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel

from app.sidecar.models import NetworkObservationEvent, SidecarSessionSummary, TrafficDirection
from app.sidecar.proxy import get_sidecar_proxy

app = FastAPI(
    title="ShadowBoard L2 Out-of-Process Observation Sidecar",
    description="Independent network egress & ingress proxy capturing verifiable L2 execution telemetry.",
    version="1.0.0",
)

router = APIRouter(prefix="/proxy", tags=["Sidecar Proxy"])


class ForwardRequestPayload(BaseModel):
    target_url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    session_id: str = "default"
    direction: str = "EGRESS"


class ExportEvidencePayload(BaseModel):
    session_id: str
    scan_id: int
    target_id: int
    target_name: str
    finding_id: str
    rule_id: str
    rule_name: str
    severity: str
    owasp_category: str
    attack_prompts: List[str]
    strategies_used: List[str]
    response_text: str
    violation_details: Dict[str, Any]
    remediation_text: str


@router.get("/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok", "component": "l2_observation_sidecar", "truth_level": "L2_PROXY_OBSERVED"}


@router.post("/observe")
async def observe_and_forward(payload: ForwardRequestPayload) -> Response:
    """Forward an outbound request through the proxy, capture telemetry, and return response."""
    proxy = get_sidecar_proxy()
    direction = TrafficDirection.EGRESS if payload.direction.upper() == "EGRESS" else TrafficDirection.INGRESS
    content = payload.body.encode("utf-8") if payload.body else None

    status_code, resp_headers, resp_bytes = await proxy.forward_and_observe(
        session_id=payload.session_id,
        method=payload.method,
        target_url=payload.target_url,
        direction=direction,
        headers=payload.headers,
        content=content,
    )

    # Filter out transfer-encoding to avoid ASGI issues
    headers_clean = {k: v for k, v in resp_headers.items() if k.lower() not in ("transfer-encoding", "content-encoding")}
    return Response(content=resp_bytes, status_code=status_code, headers=headers_clean)


@router.get("/sessions/{session_id}/events")
def get_session_events(session_id: str) -> List[NetworkObservationEvent]:
    """Retrieve all raw recorded network events for an active session."""
    proxy = get_sidecar_proxy()
    return proxy.get_session_events(session_id)


@router.get("/sessions/{session_id}/canonical")
def get_canonical_events(session_id: str) -> List[Dict[str, Any]]:
    """Retrieve canonical ShadowBoard execution events ready for verifiers."""
    proxy = get_sidecar_proxy()
    return proxy.to_canonical_execution_events(session_id)


@router.get("/sessions/{session_id}/summary")
def get_session_summary(session_id: str) -> SidecarSessionSummary:
    """Compute cryptographic summary and Merkle root over observed session events."""
    proxy = get_sidecar_proxy()
    return proxy.summarize_session(session_id)


@router.post("/sessions/{session_id}/export")
def export_evidence_package(session_id: str, payload: ExportEvidencePayload) -> Dict[str, Any]:
    """Export and cryptographically sign an L2 PROXY_OBSERVED evidence package."""
    proxy = get_sidecar_proxy()
    pkg = proxy.export_l2_evidence_package(
        session_id=session_id,
        scan_id=payload.scan_id,
        target_id=payload.target_id,
        target_name=payload.target_name,
        finding_id=payload.finding_id,
        rule_id=payload.rule_id,
        rule_name=payload.rule_name,
        severity=payload.severity,
        owasp_category=payload.owasp_category,
        attack_prompts=payload.attack_prompts,
        strategies_used=payload.strategies_used,
        response_text=payload.response_text,
        violation_details=payload.violation_details,
        remediation_text=payload.remediation_text,
    )
    return pkg.model_dump()


@router.delete("/sessions/{session_id}")
def clear_session(session_id: str) -> Dict[str, str]:
    """Clear memory buffer for a terminated session."""
    proxy = get_sidecar_proxy()
    proxy.clear_session(session_id)
    return {"status": "cleared", "session_id": session_id}


app.include_router(router)
