"""Full-Stack Integration Tests for Enterprise AI Assurance Platform Endpoints."""

import pytest
from fastapi.testclient import TestClient
from main import app

@pytest.fixture
def client():
    return TestClient(app)


def test_policy_engine_endpoints(client):
    # 1. Get templates
    t_resp = client.get("/api/policy-engine/templates")
    assert t_resp.status_code == 200
    templates = t_resp.json()
    assert "tenant_isolation" in templates
    assert "tool_governance" in templates
    assert "data_perimeter" in templates

    # 2. Compile template
    yaml_content = templates["tenant_isolation"]["yaml_content"]
    comp_resp = client.post("/api/policy-engine/compile", json={"yaml_content": yaml_content})
    assert comp_resp.status_code == 200
    comp_data = comp_resp.json()
    assert comp_data["valid"] is True
    assert comp_data["rules_count"] >= 2

    # 3. Evaluate execution trace against compiled policy
    eval_resp = client.post("/api/policy-engine/evaluate", json={
        "yaml_content": yaml_content,
        "response_text": "Here is invoice 1042",
        "execution_events": [{
            "event_type": "tool_call",
            "event_data": {
                "name": "get_invoice",
                "arguments": {"customer_id": "1042"},
                "result": {"success": True, "invoice": {"amount_usd": "$12,850.00"}}
            }
        }],
        "session_user_id": "1001",
        "target_mode": "INSTRUMENTED"
    })
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["violations_found"] >= 1
    assert any(r["violated"] and r["rule_id"] == "PAC-TENANT-001" for r in eval_data["results"])


def test_planner_surface_and_generate(client):
    # 1. Inspect Target 2 Surface
    surf_resp = client.post("/api/planner/surface?target_id=2")
    assert surf_resp.status_code == 200
    surf_data = surf_resp.json()
    assert surf_data["has_tools"] is True
    assert surf_data["has_rag"] is True
    assert "BOLA_IDOR" in surf_data["susceptible_vectors"]

    # 2. Generate Plan
    plan_resp = client.post("/api/planner/generate", json={
        "target_id": 2,
        "objective_vector": "BOLA_IDOR",
        "target_tenant": "1042",
        "session_user_id": "1001"
    })
    assert plan_resp.status_code == 200
    plan = plan_resp.json()
    assert len(plan["steps"]) == 5
    assert plan["steps"][0]["stage"] == "RECONNAISSANCE"
    assert plan["steps"][2]["stage"] == "ARGUMENT_TAMPERING"


def test_shadowboard_bench_endpoints(client):
    # 1. List benchmark agents
    agents_resp = client.get("/api/bench/agents")
    assert agents_resp.status_code == 200
    agents = agents_resp.json()
    assert len(agents) == 5

    # 2. Run benchmark suite
    run_resp = client.post("/api/bench/run", json={"mitigation_enabled": True})
    assert run_resp.status_code == 200
    suite = run_resp.json()
    assert suite["agents_tested"] == 5
    assert suite["global_detection_rate"] == round(
        suite["global_tp"] / max(1, suite["global_tp"] + suite["global_fn"]) * 100.0,
        1,
    )
    assert "results" in suite


def test_regression_baseline_and_diff(client):
    # Fetch scans to get an ID
    scans_resp = client.get("/api/scans")
    assert scans_resp.status_code == 200
    scans = scans_resp.json()
    if scans:
        scan_id = scans[0]["id"]
        # Set baseline
        base_resp = client.post("/api/regression/baseline", json={"target_id": 2, "scan_id": scan_id})
        assert base_resp.status_code == 200
        base_data = base_resp.json()
        assert base_data["target_id"] == 2

        # Get baseline
        get_base_resp = client.get("/api/regression/baseline/2")
        assert get_base_resp.status_code == 200

        # Diff
        diff_resp = client.post("/api/regression/diff", json={"target_id": 2, "current_scan_id": scan_id})
        assert diff_resp.status_code == 200
        diff_data = diff_resp.json()
        assert "ci_gate_status" in diff_data


def test_evidence_package_and_offline_verification(client):
    # Fetch findings to get a finding ID
    findings_resp = client.get("/api/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    if findings:
        f_id = findings[0]["finding_id"]
        # Get Evidence Package
        pkg_resp = client.get(f"/api/evidence/{f_id}/package")
        assert pkg_resp.status_code == 200
        pkg_data = pkg_resp.json()
        assert "proof" in pkg_data
        assert "event_chain_hash" in pkg_data["proof"]

        # Verify offline
        verify_resp = client.post("/api/evidence/verify", json={"package_data": pkg_data})
        assert verify_resp.status_code == 200
        verify_data = verify_resp.json()
        assert verify_data["verified"] is True
        assert verify_data["summary"]["verification_status"] == "CRYPTOGRAPHICALLY_VERIFIED"


def test_integrations_sarif_slack_jira(client):
    scans_resp = client.get("/api/scans")
    assert scans_resp.status_code == 200
    scans = scans_resp.json()
    if scans:
        scan_id = scans[0]["id"]
        # SARIF
        sarif_resp = client.get(f"/api/integrations/sarif/{scan_id}")
        assert sarif_resp.status_code == 200
        sarif_data = sarif_resp.json()
        assert sarif_data["version"] == "2.1.0"
        assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "ShadowBoard Enterprise AI Assurance"

        # JUnit XML
        junit_resp = client.get(f"/api/integrations/junit/{scan_id}")
        assert junit_resp.status_code == 200
        assert junit_resp.headers["content-type"] == "application/xml"
        assert "<testsuite" in junit_resp.text

    # Slack Preview
    slack_resp = client.post("/api/integrations/slack/preview", json={
        "target_name": "Meridian Knowledge Assistant",
        "scan_id": 1,
        "risk_score": 70,
        "risk_grade": "C",
        "findings": [{"severity": "CRITICAL", "rule_name": "BOLA Parameter Tampering", "status": "CONFIRMED"}]
    })
    assert slack_resp.status_code == 200
    slack_data = slack_resp.json()
    assert "blocks" in slack_data

    # Jira Preview
    jira_resp = client.post("/api/integrations/jira/preview", json={
        "target_name": "Meridian Knowledge Assistant",
        "finding": {"finding_id": "POL-BOLA-001", "severity": "CRITICAL", "rule_name": "BOLA Tampering", "remediation": "Enforce RBAC."}
    })
    assert jira_resp.status_code == 200
    jira_data = jira_resp.json()
    assert jira_data["fields"]["priority"]["name"] == "Highest"
