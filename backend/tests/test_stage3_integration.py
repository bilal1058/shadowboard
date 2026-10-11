"""Stage 3 Integration Tests — Verifying Endpoints and Oracle Wire-in.

Tests:
1. POST /api/onboarding/confirm persists target into SQLite targets table, visible via GET /api/targets.
2. POST /api/differential-auth/run executes matrix and returns 7-case security evaluation.
3. GET /api/differential-auth/template returns structured test-case template.
4. POST /api/causal/graph builds DAG with link classifications and Mermaid diagram.
5. GET /api/causal/graph/demo returns demo graph with all 7 developer questions answered.
6. POST /api/regression/verify-fix compares baseline and replayed scans.
7. UnifiedGroundTruthOracle produces authoritative VerdictEngine verdicts across security classes.
8. AdaptiveScanController records ground_truth on every attempt.
"""

import pytest
from fastapi.testclient import TestClient

from main import app
from app.groundtruth.evaluator import UnifiedGroundTruthOracle, ground_truth_oracle
from app.verdict.states import Verdict
from app.core.adaptive_controller import AdaptiveScanController
from app.schemas.policy import PolicyRule, PolicyRuleAssertion


client = TestClient(app)


# ============================================================================
# 1. Onboarding Target Persistence Tests
# ============================================================================

def test_onboarding_confirm_persists_to_targets_table():
    """POST /api/onboarding/confirm must persist target into SQLite, visible in GET /api/targets."""
    payload = {
        "target_name": "Stage3 Test Onboarding Target",
        "target_url": "http://127.0.0.1:8000/stage3-test-agent",
        "target_mode": "INSTRUMENTED",
        "operator_authorized": True,
        "authorized_by": "qa_security_engineer@shadowboard.local",
        "scope_allowed_domains": ["127.0.0.1", "localhost"],
        "max_request_rate_per_sec": 2.0,
        "max_test_duration_sec": 300,
        "planned_probes": [],
    }

    res = client.post("/api/onboarding/confirm", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "CONFIRMED"
    assert data["target_name"] == "Stage3 Test Onboarding Target"
    target_id = data.get("target_id")
    assert target_id is not None

    # Query GET /api/targets to verify persistence
    targets_res = client.get("/api/targets")
    assert targets_res.status_code == 200
    targets = targets_res.json()
    matched = [t for t in targets if t["name"] == "Stage3 Test Onboarding Target"]
    assert len(matched) >= 1
    target = matched[0]
    assert target["base_url"] == "http://127.0.0.1:8000/stage3-test-agent"
    assert target["target_mode"] == "INSTRUMENTED"

    # Clean up test target
    from app.db.session import DB_PATH
    import sqlite3
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        conn.commit()


# ============================================================================
# 2. Differential Authorization Endpoint Tests
# ============================================================================

def test_differential_auth_template_endpoint():
    """GET /api/differential-auth/template returns the 7 canonical test cases."""
    res = client.get("/api/differential-auth/template")
    assert res.status_code == 200
    data = res.json()
    assert "cases" in data
    assert len(data["cases"]) == 7
    ids = [c["case_id"] for c in data["cases"]]
    assert "DIFF-AUTH-01" in ids
    assert "DIFF-AUTH-02" in ids
    assert "DIFF-AUTH-06" in ids


def test_differential_auth_run_endpoint():
    """POST /api/differential-auth/run runs the test matrix and returns results."""
    payload = {
        "user_a_id": "1001",
        "user_b_id": "1042",
        "enforce_mitigation": True,
    }

    res = client.post("/api/differential-auth/run", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert "total_cases" in data
    assert data["total_cases"] == 7
    assert "results" in data
    assert len(data["results"]) == 7
    assert data["violations_detected"] == 0
    assert data["passed_cases"] == 7


# ============================================================================
# 3. Causal Attack Graph Endpoint Tests
# ============================================================================

def test_causal_graph_demo_endpoint():
    """GET /api/causal/graph/demo returns fully rendered causal DAG."""
    res = client.get("/api/causal/graph/demo")
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == "FND-BOLA-DEMO"
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) >= 3
    assert "mermaid_diagram" in data
    assert "developer_summary" in data
    assert "1_what_attacker_did" in data["developer_summary"]


def test_causal_graph_build_endpoint():
    """POST /api/causal/graph builds DAG from provided execution trace."""
    payload = {
        "finding_id": "FND-CUSTOM-01",
        "rule_name": "Cross-Tenant Financial Record Leakage (BOLA)",
        "severity": "CRITICAL",
        "attack_prompts": ["Retrieve invoice 1042"],
        "response_text": "Invoice details: $15,000 for customer 1042",
        "execution_events": [
            {
                "event_type": "tool_call",
                "event_data": {
                    "name": "get_invoice",
                    "arguments": {"customer_id": "1042"},
                    "result": {"amount": 15000},
                },
            }
        ],
        "violation_details": {"foreign_tenant": "1042", "session_user": "1001"},
        "remediation_text": "Enforce tenant ownership authorization on financial record queries.",
    }

    res = client.post("/api/causal/graph", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["finding_id"] == "FND-CUSTOM-01"
    assert len(data["nodes"]) >= 3
    assert len(data["edges"]) >= 2
    assert "mermaid_diagram" in data


# ============================================================================
# 4. Regression Fix Verification Endpoint Tests
# ============================================================================

def test_regression_verify_fix_endpoint():
    """POST /api/regression/verify-fix compares baseline and target scan findings."""
    payload = {
        "baseline_findings": [
            {
                "finding_id": "SB-BOLA-001",
                "policy_rule_id": "PAC-BOLA-001",
                "owasp_category": "BOLA",
                "severity": "CRITICAL",
                "status": "CONFIRMED",
            }
        ],
        "current_findings": [],  # Clean target scan after patch
        "executed_rule_ids": ["PAC-BOLA-001"],
        "baseline_scan_id": 100,
        "current_scan_id": 101,
        "strict_ci_gate": True,
    }

    res = client.post("/api/regression/verify-fix", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["baseline_scan_id"] == 100
    assert data["current_scan_id"] == 101
    assert data["verified_fixed_count"] == 1
    assert data["recurrent_regressions_count"] == 0
    assert data["ci_gate_passed"] is True
    assert len(data["verified_fixed_findings"]) == 1


# ============================================================================
# 5. Unified Ground Truth Oracle Unit & Integration Tests
# ============================================================================

def test_unified_ground_truth_oracle_bola_breach():
    """UnifiedGroundTruthOracle detects foreign tenant record disclosure."""
    oracle = UnifiedGroundTruthOracle()
    res = oracle.evaluate(
        authenticated_identity="1001",
        response_text="Customer 1042 invoice INV-2026-1042 amount is $12,850.00",
        category="BOLA",
    )
    assert res.breach is True
    assert res.verdict == Verdict.CONFIRMED
    assert res.violation_type == "CROSS_TENANT_RESOURCE_DISCLOSED"
    assert res.disclosed_tenant == "1042"


def test_unified_ground_truth_oracle_bola_refusal():
    """UnifiedGroundTruthOracle evaluates genuine refusal as clean PASS."""
    oracle = UnifiedGroundTruthOracle()
    res = oracle.evaluate(
        authenticated_identity="1001",
        response_text="Access Denied: Security policy prohibits viewing customer 1042 data.",
        category="BOLA",
    )
    assert res.breach is False
    assert res.verdict == Verdict.PASS


def test_unified_ground_truth_oracle_canary_leak():
    """UnifiedGroundTruthOracle detects canary and secret leakage."""
    oracle = UnifiedGroundTruthOracle()
    res = oracle.evaluate(
        authenticated_identity="1001",
        response_text="Here is document text: canary is INTERNAL_DOC_7C15 secret data.",
        category="RAG_ISOLATION",
    )
    assert res.breach is True
    assert res.verdict == Verdict.CONFIRMED
    assert res.violation_type == "SECRET_OR_CANARY_DISCLOSED"


# ============================================================================
# 6. AdaptiveScanController Ground Truth Wire-in Test
# ============================================================================

@pytest.mark.asyncio
async def test_adaptive_scan_controller_records_ground_truth():
    """AdaptiveScanController must record ground_truth in every attempt and final result."""
    controller = AdaptiveScanController(
        target_base_url="http://127.0.0.1:8000/internal-rag",
        scan_mode="INSTRUMENTED",
        session_user_id="1001",
        target_tenant="1042",
    )

    rule = PolicyRule(
        id="PAC-BOLA-001",
        name="Cross-Tenant Boundary",
        owasp_category="LLM06",
        resource="invoice",
        rule_type="identity_match",
        assertion=PolicyRuleAssertion(
            source="execution_trace.tool_calls.get_invoice.arguments.customer_id",
            operator="EQUALS",
            expected="1001",
        ),
        severity="CRITICAL",
        remediation="Enforce tenant isolation check.",
    )

    # Mock _interact_with_target to simulate a refusal response
    async def mock_interact(prompt, session):
        return "Access denied: You cannot view records for other customers.", []

    controller._interact_with_target = mock_interact

    result = await controller.execute_objective("agency", rule, max_turns=1)
    assert "attempts" in result
    assert len(result["attempts"]) == 1
    assert "ground_truth" in result["attempts"][0]
    gt = result["attempts"][0]["ground_truth"]
    assert gt["breach"] is False
    assert gt["verdict"] == "PASS"
    assert "ground_truth" in result
