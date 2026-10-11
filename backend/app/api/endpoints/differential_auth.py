"""API Router for Differential Authorization Matrix Testing."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter
from pydantic import BaseModel

from app.differential_auth.matrix import DifferentialAuthMatrix
from app.reference_agent.agent import MultiToolReferenceAgent

router = APIRouter(prefix="/differential-auth", tags=["Differential Authorization Matrix"])


class DifferentialAuthRunRequest(BaseModel):
    user_a_id: str = "tenant_alpha"
    user_b_id: str = "tenant_beta"
    enforce_mitigation: bool = True


@router.post("/run")
async def run_differential_auth_matrix(request: DifferentialAuthRunRequest) -> Dict[str, Any]:
    """Executes the systematic Identity x Role x Resource x Action differential matrix."""
    agent = MultiToolReferenceAgent(mitigated=request.enforce_mitigation)
    results = await DifferentialAuthMatrix.run_matrix(
        agent=agent,
        user_a_id=request.user_a_id,
        user_b_id=request.user_b_id,
        enforce_mitigation=request.enforce_mitigation,
    )

    passed_count = sum(1 for r in results if r.passed)
    violation_count = sum(1 for r in results if not r.passed)

    serialized_results = [
        {
            "case_id": r.case.case_id,
            "description": r.case.description,
            "invariant_category": r.case.invariant_category,
            "caller": r.case.authenticated_identity,
            "role": r.case.authenticated_role,
            "target_owner": r.case.target_resource_owner,
            "action_type": r.case.action_type,
            "tool_name": r.case.tool_name,
            "expected_outcome": r.case.expected_outcome.value,
            "actual_outcome": r.actual_outcome,
            "passed": r.passed,
            "discrepancy_details": r.discrepancy_details,
            "response_snippet": r.response_snippet,
        }
        for r in results
    ]

    return {
        "total_cases": len(results),
        "passed_cases": passed_count,
        "violations_detected": violation_count,
        "mitigation_enforced": request.enforce_mitigation,
        "results": serialized_results,
    }


@router.get("/template")
async def get_differential_auth_template() -> Dict[str, Any]:
    """Returns the standard differential authorization matrix test cases."""
    cases = DifferentialAuthMatrix.generate_standard_matrix()
    return {
        "total_cases": len(cases),
        "cases": [
            {
                "case_id": c.case_id,
                "description": c.description,
                "invariant_category": c.invariant_category,
                "caller": c.authenticated_identity,
                "role": c.authenticated_role,
                "target_owner": c.target_resource_owner,
                "action_type": c.action_type,
                "tool_name": c.tool_name,
                "expected_outcome": c.expected_outcome.value,
                "vulnerability_if_allowed": c.vulnerability_if_allowed,
                "remediation_guidance": c.remediation_guidance,
            }
            for c in cases
        ],
    }
