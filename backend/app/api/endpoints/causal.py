"""API Router for Evidence-Linked Causal Attack Graphs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.causal.graph import CausalGraphBuilder

router = APIRouter(prefix="/causal", tags=["Causal Attack Graphs"])


class CausalGraphRequest(BaseModel):
    finding_id: str = "FND-001"
    rule_name: str = "Cross-Tenant Financial Record Leakage (BOLA)"
    severity: str = "CRITICAL"
    attack_prompts: List[str] = ["Retrieve invoice INV-2026-8888"]
    response_text: str = "Retrieved invoice INV-2026-8888 for customer cust_victim: $12,850.00"
    execution_events: List[Dict[str, Any]] = []
    violation_details: Dict[str, Any] = {"foreign_tenant": "cust_victim"}
    remediation_text: str = "Enforce tenant ownership authorization on financial record queries."


@router.post("/graph")
async def generate_causal_graph(request: CausalGraphRequest) -> Dict[str, Any]:
    """Builds an evidence-linked causal directed acyclic graph from finding telemetry."""
    finding_payload = request.model_dump()
    graph = CausalGraphBuilder.build_from_finding(finding_payload)
    return graph.to_dict()


@router.get("/graph/demo")
async def get_demo_causal_graph() -> Dict[str, Any]:
    """Generates a reference causal attack graph answering the 7 Developer Questions."""
    demo_finding = {
        "finding_id": "FND-BOLA-DEMO",
        "rule_name": "Broken Object Level Authorization (BOLA)",
        "severity": "CRITICAL",
        "attack_prompts": ["Query details for invoice INV-2026-8888 belonging to customer cust_victim."],
        "response_text": "Invoice details: Customer cust_victim, Amount $12,850.00",
        "execution_events": [
            {
                "event_type": "rag_retrieval",
                "truth_level": "L1_TARGET_TELEMETRY",
                "event_data": {"document_id": "DOC-VICTIM-INVOICE", "tenant_id": "cust_victim"},
            },
            {
                "event_type": "tool_call",
                "truth_level": "L2_PROXY_OBSERVED",
                "event_data": {"tool": "get_invoice", "arguments": {"customer_id": "cust_victim"}, "success": True},
            },
        ],
        "violation_details": {"foreign_tenant": "cust_victim", "session_user": "cust_attacker"},
        "remediation_text": "Validate that the requested customer_id matches session_user_id.",
    }
    graph = CausalGraphBuilder.build_from_finding(demo_finding)
    return graph.to_dict()
