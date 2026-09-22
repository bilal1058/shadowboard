"""Unit tests for Continuous AI Security Regression Testing Engine."""

import pytest
from app.regression import ContinuousRegressionEngine, CIGatePolicy


def test_create_and_compare_baseline_improvement():
    # Baseline scan with 2 vulnerabilities
    baseline_findings = [
        {"finding_id": "POL-BOLA-001", "status": "CONFIRMED", "severity": "CRITICAL", "rule_name": "Invoice Isolation"},
        {"finding_id": "POL-LEAK-001", "status": "CONFIRMED", "severity": "HIGH", "rule_name": "Canary Leakage"},
    ]
    baseline = ContinuousRegressionEngine.create_baseline(
        target_id=2,
        scan_id=10,
        risk_score=40,
        risk_grade="D",
        findings_list=baseline_findings,
    )
    assert baseline.baseline_id == "base_tgt2_scan10"
    assert len(baseline.findings) == 2

    # Regression scan: POL-BOLA-001 fixed, POL-LEAK-001 also fixed!
    current_findings = [
        {"finding_id": "POL-BOLA-001", "status": "PASS", "severity": "CRITICAL", "rule_name": "Invoice Isolation"},
        {"finding_id": "POL-LEAK-001", "status": "PASS", "severity": "HIGH", "rule_name": "Canary Leakage"},
    ]
    comparison = ContinuousRegressionEngine.compare_against_baseline(
        baseline=baseline,
        current_scan_id=11,
        current_score=100,
        current_grade="A",
        current_findings=current_findings,
    )

    assert comparison.score_delta == +60
    assert len(comparison.resolved_vulnerabilities) == 2
    assert len(comparison.new_vulnerabilities) == 0
    assert comparison.ci_gate_status == "PASSED"
    assert "IMPROVEMENT" in comparison.summary_narrative


def test_regression_detects_new_vulnerability():
    # Baseline was clean
    baseline = ContinuousRegressionEngine.create_baseline(
        target_id=2,
        scan_id=1,
        risk_score=100,
        risk_grade="A",
        findings_list=[
            {"finding_id": "POL-BOLA-001", "status": "PASS", "severity": "CRITICAL"},
        ],
    )

    # Developer pushed change that introduced BOLA!
    current_findings = [
        {"finding_id": "POL-BOLA-001", "status": "CONFIRMED", "severity": "CRITICAL", "rule_name": "Invoice Isolation"},
    ]
    comparison = ContinuousRegressionEngine.compare_against_baseline(
        baseline=baseline,
        current_scan_id=2,
        current_score=70,
        current_grade="C",
        current_findings=current_findings,
        gate_policy=CIGatePolicy(fail_on_critical=True, fail_on_new_vulnerabilities=True),
    )

    assert comparison.score_delta == -30
    assert len(comparison.new_vulnerabilities) == 1
    assert comparison.ci_gate_status == "FAILED"
    assert any("CRITICAL" in r for r in comparison.ci_gate_reasons)
    assert any("NEW security regression" in r for r in comparison.ci_gate_reasons)


def test_semantic_fingerprint_survives_generated_id_and_evidence_changes():
    baseline = ContinuousRegressionEngine.create_baseline(
        target_id=7,
        scan_id=10,
        risk_score=40,
        risk_grade="F",
        findings_list=[{
            "finding_id": "generated-old-id",
            "status": "CONFIRMED",
            "severity": "CRITICAL",
            "security_property": "owner_scoped_read",
            "resource": "workspace",
            "action": "read",
            "principal_resource_relation": "principal_not_owner",
            "evidence_hash": "old-evidence",
        }],
    )

    comparison = ContinuousRegressionEngine.compare_against_baseline(
        baseline=baseline,
        current_scan_id=11,
        current_score=100,
        current_grade="A",
        current_findings=[{
            "finding_id": "generated-new-id",
            "status": "PASS",
            "severity": "CRITICAL",
            "security_property": "owner_scoped_read",
            "resource": "workspace",
            "action": "read",
            "principal_resource_relation": "principal_not_owner",
            "evidence_hash": "new-evidence",
        }],
    )

    assert len(comparison.resolved_vulnerabilities) == 1
    assert len(comparison.persisting_vulnerabilities) == 0


def test_semantic_fingerprint_separates_different_security_properties():
    baseline = ContinuousRegressionEngine.create_baseline(
        target_id=7,
        scan_id=10,
        risk_score=40,
        risk_grade="F",
        findings_list=[{
            "finding_id": "old-bola",
            "status": "CONFIRMED",
            "severity": "CRITICAL",
            "security_property": "owner_scoped_read",
        }],
    )
    comparison = ContinuousRegressionEngine.compare_against_baseline(
        baseline=baseline,
        current_scan_id=11,
        current_score=40,
        current_grade="F",
        current_findings=[{
            "finding_id": "new-egress",
            "status": "CONFIRMED",
            "severity": "HIGH",
            "security_property": "unauthorized_network_egress",
        }],
    )

    assert len(comparison.resolved_vulnerabilities) == 1
    assert len(comparison.new_vulnerabilities) == 1
