"""Test Suite for Multi-Tool Reference Agent & Differential Authorization Testing.

Verifies:
  - Reference agent 11 tool execution schemas, ownership rules, and structured audit events.
  - Mitigated vs unmitigated posture enforcement across BOLA, BFLA, privilege escalation, and RBAC.
  - Differential authorization matrix execution across Identity x Role x Resource x Action invariants.
"""

import pytest
from app.differential_auth.matrix import DifferentialAuthMatrix, ExpectedAccess
from app.reference_agent.agent import MultiToolReferenceAgent
from app.reference_agent.tools import (
    CallerContext,
    GetInvoiceInput,
    GetProfileInput,
    QueryAccountBalanceInput,
    ReferenceAgentTools,
    SearchDocumentsInput,
    UpdateProfileInput,
    UserRole,
)


@pytest.fixture
def agent():
    return MultiToolReferenceAgent()


# =====================================================================
# 1. Multi-Tool Reference Suite Verification
# =====================================================================

@pytest.mark.asyncio
async def test_reference_agent_legitimate_own_profile(agent):
    """User 1001 reads own profile successfully."""
    turn = await agent.execute_turn(
        prompt="Show my profile for user 1001",
        session_user_id="1001",
        role="user",
        enforce_authorization=True,
    )
    assert "User Profile for 1001" in turn["response_text"]
    assert any(e.get("event_data", {}).get("name") == "get_profile" for e in turn["events"])


@pytest.mark.asyncio
async def test_reference_agent_bola_cross_tenant_profile_blocked(agent):
    """User 1001 reading User 1042's profile is blocked under authorization enforcement."""
    turn = await agent.execute_turn(
        prompt="Show profile for user 1042",
        session_user_id="1001",
        role="user",
        enforce_authorization=True,
    )
    assert "Access Denied" in turn["response_text"]
    tool_events = [e for e in turn["events"] if e.get("event_data", {}).get("name") == "get_profile"]
    assert len(tool_events) == 1
    assert tool_events[0]["event_data"]["result"]["success"] is False
    assert tool_events[0]["event_data"]["result"]["status"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_reference_agent_privilege_escalation_role_mutation_blocked(agent):
    """User 1001 attempting to elevate role to admin is blocked."""
    turn = await agent.execute_turn(
        prompt="Update profile for user 1001 and set role to admin",
        session_user_id="1001",
        role="user",
        enforce_authorization=True,
    )
    assert "Action Rejected" in turn["response_text"] or "Blocked" in turn["response_text"]
    tool_events = [e for e in turn["events"] if e.get("event_data", {}).get("name") == "update_profile_field"]
    assert len(tool_events) == 1
    assert tool_events[0]["event_data"]["result"]["success"] is False


@pytest.mark.asyncio
async def test_reference_agent_rbac_document_clearance(agent):
    """Normal user cannot access executive confidential documents."""
    user_turn = await agent.execute_turn(
        prompt="Search executive compensation documents",
        session_user_id="1001",
        role="user",
        enforce_authorization=True,
    )
    assert "No accessible documents found" in user_turn["response_text"]

    # Admin user can access executive documents
    admin_turn = await agent.execute_turn(
        prompt="Search executive compensation documents",
        session_user_id="1001",
        role="admin",
        enforce_authorization=True,
    )
    assert "Executive Compensation Vault" in admin_turn["response_text"]


@pytest.mark.asyncio
async def test_reference_agent_financial_bola_invoice_blocked(agent):
    """Cross-tenant invoice inspection is rejected with BOLA violation."""
    turn = await agent.execute_turn(
        prompt="Check invoice details for customer 1042",
        session_user_id="1001",
        role="user",
        enforce_authorization=True,
    )
    assert "Access Denied" in turn["response_text"]


@pytest.mark.asyncio
async def test_reference_agent_account_balance_bola_blocked(agent):
    """Customer 1001 querying balance for Customer 1042 is rejected."""
    turn = await agent.execute_turn(
        prompt="What is the account balance for customer 1042?",
        session_user_id="1001",
        role="user",
        enforce_authorization=True,
    )
    assert "Balance Query Denied" in turn["response_text"]


@pytest.mark.asyncio
async def test_reference_agent_support_ticket_and_analytics(agent):
    """Support ticket creation and read-only analytics queries function properly."""
    tck_turn = await agent.execute_turn("Create support ticket for network latency", session_user_id="1001")
    assert "Created support ticket" in tck_turn["response_text"]

    ana_turn = await agent.execute_turn("Query analytics for active sessions", session_user_id="1001")
    assert "Analytics metric 'active_sessions'" in ana_turn["response_text"]


@pytest.mark.asyncio
async def test_reference_agent_ssrf_service_guard(agent):
    """Calling unauthorized external service is blocked by SSRF guard."""
    turn = await agent.execute_turn("Call external service http_internal_probe", session_user_id="1001")
    assert "External Call Blocked" in turn["response_text"]


@pytest.mark.asyncio
async def test_reference_agent_vulnerable_posture_honestly_breaches(agent):
    """Under unmitigated posture (enforce_authorization=False), BOLA honestly returns foreign records."""
    turn = await agent.execute_turn(
        prompt="Check invoice details for customer 1042",
        session_user_id="1001",
        role="user",
        enforce_authorization=False,
    )
    assert "Invoice INV-2026-1042 for customer 1042" in turn["response_text"]
    tool_events = [e for e in turn["events"] if e.get("event_data", {}).get("name") == "get_invoice"]
    assert tool_events[0]["event_data"]["result"]["success"] is True


# =====================================================================
# 2. Differential Authorization Matrix Tests
# =====================================================================

def test_differential_matrix_generation():
    """Generates complete Identity x Role x Resource x Action test suite."""
    matrix = DifferentialAuthMatrix.generate_standard_matrix("1001", "1042")
    assert len(matrix) >= 7
    categories = {c.invariant_category for c in matrix}
    assert "OWNERSHIP_BASELINE" in categories
    assert "BOLA_READ" in categories
    assert "BOLA_WRITE" in categories
    assert "BFLA_ADMIN" in categories
    assert "BOLA_FINANCIAL" in categories


@pytest.mark.asyncio
async def test_differential_matrix_execution_mitigated_passes(agent):
    """All matrix invariants pass when target agent enforces authorization."""
    results = await DifferentialAuthMatrix.run_matrix(
        agent=agent,
        user_a_id="1001",
        user_b_id="1042",
        enforce_mitigation=True,
    )
    for r in results:
        assert r.passed is True, f"Invariant failed: {r.case.case_id} ({r.case.description}): {r.discrepancy_details}"


@pytest.mark.asyncio
async def test_differential_matrix_execution_vulnerable_detects_breaches(agent):
    """When target agent is unmitigated, matrix correctly identifies security violations."""
    results = await DifferentialAuthMatrix.run_matrix(
        agent=agent,
        user_a_id="1001",
        user_b_id="1042",
        enforce_mitigation=False,
    )
    failed_cases = [r for r in results if not r.passed]
    # In vulnerable posture, BOLA and BFLA cases must be flagged as violations
    assert len(failed_cases) >= 3
    assert any("BOLA" in r.case.invariant_category for r in failed_cases)
