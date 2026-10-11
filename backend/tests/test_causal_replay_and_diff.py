"""Test Suite for Causal Attack Graphs, Replayable Evidence Bundles, and Security Regression Diffs."""

import pytest
from app.causal.graph import CausalGraphBuilder, LinkType, NodeType
from app.evidence.replay import EvidenceReplayEngine
from app.reference_agent.agent import MultiToolReferenceAgent
from app.regression.diff import RegressionDiffEngine


# =====================================================================
# 1. Causal Attack Graph Tests
# =====================================================================

def test_causal_graph_builder_structure():
    """Builds DAG distinguishing observed, correlated, and inferred causal edges."""
    events = [
        {
            "event_type": "tool_call",
            "event_data": {
                "name": "get_invoice",
                "arguments": {"customer_id": "1042"},
                "result": {"invoice_id": "INV-2026-1042", "amount": "$12,850.00"},
            },
        }
    ]
    graph = CausalGraphBuilder.build_graph(
        finding_id="FND-01",
        rule_id="PAC-BOLA-001",
        severity="CRITICAL",
        attack_prompt="Show invoice for customer 1042",
        response_text="Invoice INV-2026-1042: $12,850.00",
        execution_events=events,
        violation_type="BOLA",
        session_user_id="1001",
        target_resource="1042",
    )

    assert len(graph.nodes) == 4
    node_types = [n.node_type for n in graph.nodes]
    assert NodeType.USER_INPUT in node_types
    assert NodeType.TOOL_INVOCATION in node_types
    assert NodeType.SECURITY_BOUNDARY in node_types
    assert NodeType.RESPONSE_EGRESS in node_types

    # Verify edge types
    edge_types = [e.link_type for e in graph.edges]
    assert LinkType.DIRECTLY_OBSERVED in edge_types
    assert LinkType.CORRELATED in edge_types

    # Verify 7 Developer Questions answered
    summary = graph.developer_summary
    assert "1_what_attacker_did" in summary
    assert "2_action_agent_took" in summary
    assert "3_boundary_crossed" in summary
    assert "4_data_affected" in summary
    assert "5_evidence_proves_finding" in summary
    assert "6_what_should_be_fixed" in summary
    assert "7_post_patch_status" in summary

    # Verify Mermaid rendering
    mermaid = graph.to_mermaid()
    assert mermaid.startswith("graph TD")
    assert "N_INPUT" in mermaid
    assert "N_TOOL" in mermaid


# =====================================================================
# 2. Evidence Replay Engine Tests
# =====================================================================

def test_evidence_replay_generate_curl():
    """Generates portable reproduction command from bundle."""
    pkg = {
        "finding_id": "FND-02",
        "target_name": "Meridian Assistant",
        "attack_prompts": ["Query customer 1042 invoice"],
    }
    cmd = EvidenceReplayEngine.generate_reproduction_command(pkg)
    assert "curl -X POST" in cmd
    assert "1042" in cmd
    assert "X-Customer-ID: 1001" in cmd


@pytest.mark.asyncio
async def test_evidence_replay_against_agent_verifies_fix():
    """Replay against mitigated agent proves the exploit was fixed."""
    agent = MultiToolReferenceAgent()
    pkg = {
        "package_id": "PKG-TEST-01",
        "finding_id": "FND-BOLA-01",
        "rule_id": "PAC-BOLA-001",
        "severity": "CRITICAL",
        "attack_prompts": ["Check invoice details for customer 1042"],
        "response_text": "Invoice INV-2026-1042: $12,850.00",
    }

    # 1. Replay against mitigated agent -> VERIFIED_FIXED
    report_mitigated = await EvidenceReplayEngine.replay_against_target(
        pkg_data=pkg,
        target_executor=agent,
        session_user_id="1001",
        mitigation_enabled=True,
    )
    assert report_mitigated.is_fix_verified is True
    assert report_mitigated.status_change == "VERIFIED_FIXED"

    # 2. Replay against unmitigated agent -> STILL_VULNERABLE
    report_vulnerable = await EvidenceReplayEngine.replay_against_target(
        pkg_data=pkg,
        target_executor=agent,
        session_user_id="1001",
        mitigation_enabled=False,
    )
    assert report_vulnerable.is_fix_verified is False
    assert report_vulnerable.status_change == "STILL_VULNERABLE"


# =====================================================================
# 3. Security Regression Diff Tests
# =====================================================================

def test_regression_diff_distinguishes_verified_fix_from_unverified_omission():
    """Rule: A missing finding is NOT a fix unless the test actually re-ran under candidate run."""
    baseline_findings = [
        {"rule_id": "PAC-BOLA-01", "severity": "CRITICAL", "name": "BOLA Invoice"},
        {"rule_id": "PAC-LEAK-02", "severity": "HIGH", "name": "Secret Leak"},
    ]
    current_findings = []

    # Case A: Only PAC-BOLA-01 was re-executed. PAC-LEAK-02 test was omitted/failed!
    retested_rules = {"PAC-BOLA-01"}

    diff = RegressionDiffEngine.compare_scans(
        baseline_findings=baseline_findings,
        current_findings=current_findings,
        executed_rule_ids_in_current=retested_rules,
    )

    # PAC-BOLA-01 was re-tested and clean -> VERIFIED FIX
    assert len(diff.verified_fixed_findings) == 1
    assert diff.verified_fixed_findings[0]["rule_id"] == "PAC-BOLA-01"

    # PAC-LEAK-02 was NOT re-tested -> UNVERIFIED MISSING (NOT a fix!)
    assert len(diff.unverified_missing_findings) == 1
    assert diff.unverified_missing_findings[0]["rule_id"] == "PAC-LEAK-02"


def test_regression_diff_ci_gate_blocks_new_critical():
    """CI gate fails when new critical or high findings appear."""
    baseline_findings = []
    current_findings = [
        {"rule_id": "PAC-BOLA-01", "severity": "CRITICAL", "name": "New BOLA Breach"}
    ]
    diff = RegressionDiffEngine.compare_scans(
        baseline_findings=baseline_findings,
        current_findings=current_findings,
        strict_ci_gate=True,
    )
    assert diff.ci_gate_passed is False
    assert "new CRITICAL/HIGH" in diff.ci_gate_reason
