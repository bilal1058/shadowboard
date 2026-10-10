"""Comprehensive Test Suite for Executive Security Report Generator.

Validates boardroom-ready PDF and HTML report generation:
1. Risk score trend sparklines with historical trajectory
2. 2D Findings matrix (OWASP Top 10 for LLMs x Severity)
3. Remediation progress tracker with actionable engineering playbooks
4. Cryptographic evidence integrity records (SHA-256 Merkle chain & Ed25519)
5. Export to HTML and PDF via FastAPI endpoints
"""

import pytest
from starlette.testclient import TestClient

from app.reports.executive_report_builder import (
    build_sparkline_trend_data,
    build_findings_matrix,
    build_remediation_items,
    build_cryptographic_evidence_record,
    build_full_executive_report_model,
)
from app.reports.pdf_generator import generate_scan_pdf_report
from app.reports.html_generator import generate_scan_html_report
from main import app


def test_sparkline_trend_computation():
    """Validates multi-run historical score trajectory and fallback calculations."""
    scan_data = {"id": 4, "target_id": 2, "overall_score": 90, "mitigation_enabled": True}
    history_runs = [
        {"id": 1, "overall_score": 35},
        {"id": 2, "overall_score": 60},
        {"id": 3, "overall_score": 75},
        {"id": 4, "overall_score": 90},
    ]

    sparkline = build_sparkline_trend_data(scan_data, history_runs)
    assert sparkline["scores"] == [35, 60, 75, 90]
    assert sparkline["current_score"] == 90
    assert sparkline["baseline_score"] == 35
    assert sparkline["delta_str"] == "+55 pts"
    assert sparkline["direction"] == "IMPROVING"
    assert sparkline["total_runs"] == 4

    # Single-run fallback check
    single_run = build_sparkline_trend_data(scan_data, None)
    assert len(single_run["scores"]) >= 1
    assert single_run["current_score"] == 90


def test_findings_matrix_cross_tabulation():
    """Validates 2D cross-tabulation of OWASP categories by severity."""
    mock_findings = [
        {"finding_id": "F-01", "owasp_category": "LLM01: Prompt Injection", "severity": "CRITICAL"},
        {"finding_id": "F-02", "owasp_category": "LLM01: Prompt Injection", "severity": "HIGH"},
        {"finding_id": "F-03", "owasp_category": "LLM06: Excessive Agency / BOLA", "severity": "CRITICAL"},
        {"finding_id": "F-04", "owasp_category": "LLM02: Sensitive Info Leakage", "severity": "MEDIUM"},
        {"finding_id": "F-05", "owasp_category": "LLM07: System Prompt Leakage", "severity": "LOW"},
    ]

    matrix = build_findings_matrix(mock_findings)
    assert "rows" in matrix
    assert "totals" in matrix
    totals = matrix["totals"]

    assert totals["CRITICAL"] == 2
    assert totals["HIGH"] == 1
    assert totals["MEDIUM"] == 1
    assert totals["LOW"] == 1
    assert totals["grand_total"] == 5

    # Check LLM01 row has 1 CRITICAL, 1 HIGH
    llm01_row = next(r for r in matrix["rows"] if r["code"] == "LLM01")
    assert llm01_row["CRITICAL"] == 1
    assert llm01_row["HIGH"] == 1
    assert llm01_row["total"] == 2


def test_remediation_items_and_progress():
    """Validates actionable developer remediation playbooks and SLAs."""
    scan_unmitigated = {"id": 1, "mitigation_enabled": False}
    findings = [
        {"owasp_category": "LLM06: BOLA Violation", "severity": "CRITICAL"}
    ]

    items_unmitigated = build_remediation_items(scan_unmitigated, findings)
    assert len(items_unmitigated) >= 4
    
    # BOLA playbook must be open when unmitigated and active finding present
    bola_item = next(i for i in items_unmitigated if i["id"] == "REM-BOLA-01")
    assert bola_item["status"] == "OPEN (ACTION REQUIRED)"
    assert "code_playbook" in bola_item
    assert "verification_cmd" in bola_item
    assert "sla" in bola_item
    assert "owner" in bola_item

    # Mitigated scan should mark items as VERIFIED MITIGATED
    scan_mitigated = {"id": 2, "mitigation_enabled": True}
    items_mitigated = build_remediation_items(scan_mitigated, findings)
    bola_mitigated = next(i for i in items_mitigated if i["id"] == "REM-BOLA-01")
    assert bola_mitigated["status"] == "VERIFIED MITIGATED"


def test_cryptographic_evidence_integrity_record():
    """Validates SHA-256 Merkle root, Ed25519 signature, and CLI verifier."""
    scan_data = {"id": 10, "target_id": 2, "overall_score": 100, "risk_grade": "A"}
    findings = [{"finding_id": "F-01", "evidence_hash": "a" * 64, "severity": "LOW"}]

    record = build_cryptographic_evidence_record(scan_data, findings)
    assert len(record["merkle_root"]) == 64
    assert len(record["manifest_hash"]) == 64
    assert len(record["signature_ed25519"]) > 32
    assert record["algorithm"] == "ED25519-SHA512-RFC8032"
    assert "python -m app.evidence.standalone_verifier" in record["verification_cli"]
    assert record["ledger_record_id"].startswith("LEDGER-SB-0010-")


def test_full_executive_report_model():
    """Validates complete executive report assembly."""
    scan_data = {
        "id": 1,
        "target_id": 2,
        "target_name": "Production Customer Support Agent",
        "overall_score": 88,
        "risk_grade": "B",
        "mitigation_enabled": True
    }
    findings = [
        {"finding_id": "F-01", "owasp_category": "LLM01", "severity": "HIGH", "evidence_hash": "b" * 64}
    ]

    model = build_full_executive_report_model(scan_data, findings)
    assert model["scan_id"] == 1
    assert model["overall_score"] == 88
    assert model["risk_grade"] == "B"
    assert model["confirmed_count"] == 1
    assert "sparkline" in model
    assert "matrix" in model
    assert "remediation_items" in model
    assert "crypto_record" in model
    assert model["remediation_percent"] >= 0


def test_pdf_report_generation():
    """Validates ReportLab PDF generation with vector sparklines and tables."""
    scan_data = {
        "id": 1,
        "target_id": 2,
        "target_name": "Healthcare Assistant Agent",
        "overall_score": 92,
        "risk_grade": "A",
        "mitigation_enabled": True
    }
    findings = [
        {
            "finding_id": "F-01",
            "title": "BOLA Parameter Hijack",
            "severity": "CRITICAL",
            "policy_name": "Kernel Tool Access Control",
            "owasp_category": "LLM06: Excessive Agency",
            "evidence_hash": "c" * 64,
            "attacker_prompt": "Retrieve patient records for user ID 999",
            "target_response": "Refused: unauthorized access denied"
        }
    ]
    history_runs = [
        {"id": 1, "overall_score": 45},
        {"id": 2, "overall_score": 70},
        {"id": 3, "overall_score": 92}
    ]

    pdf_bytes = generate_scan_pdf_report(scan_data, findings, history_runs=history_runs)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 5000
    assert pdf_bytes.startswith(b"%PDF")

    # Also test empty findings
    clean_pdf = generate_scan_pdf_report(scan_data, [])
    assert isinstance(clean_pdf, bytes)
    assert clean_pdf.startswith(b"%PDF")


def test_html_report_generation():
    """Validates self-contained HTML executive report generation."""
    scan_data = {
        "id": 1,
        "target_id": 2,
        "target_name": "Enterprise FinTech Banking Agent",
        "overall_score": 85,
        "risk_grade": "B",
        "mitigation_enabled": True
    }
    findings = [
        {
            "finding_id": "F-01",
            "title": "Indirect Prompt Injection in Invoice Markdown",
            "severity": "HIGH",
            "owasp_category": "LLM01: Prompt Injection",
            "evidence_hash": "d" * 64
        }
    ]
    history_runs = [
        {"id": 1, "overall_score": 40},
        {"id": 2, "overall_score": 85}
    ]

    html = generate_scan_html_report(scan_data, findings, history_runs=history_runs)
    assert isinstance(html, str)
    assert html.startswith("<!DOCTYPE html>")
    assert "<svg viewBox=" in html
    assert "Historical Risk Posture Trend" in html
    assert "Findings Matrix (OWASP" in html
    assert "Remediation Progress Tracker" in html
    assert "Cryptographic Evidence Integrity Certificate" in html
    assert "@media print" in html
    assert "ED25519" in html
    assert "SHA-256" in html


def test_fastapi_report_endpoints():
    """Validates API endpoints for PDF and HTML executive reports."""
    client = TestClient(app)

    # Fetch scan runs to test existing scans
    list_res = client.get("/api/scans")
    assert list_res.status_code == 200
    scans = list_res.json()
    if scans:
        scan_id = scans[0]["id"]
        
        # Test PDF export
        pdf_res = client.get(f"/api/scans/{scan_id}/export/pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"] == "application/pdf"
        assert pdf_res.content.startswith(b"%PDF")

        # Test HTML export via /api/scans/{scan_id}/export/html
        html_res = client.get(f"/api/scans/{scan_id}/export/html")
        assert html_res.status_code == 200
        assert "text/html" in html_res.headers["content-type"]
        assert "<!DOCTYPE html>" in html_res.text
        assert "ShadowBoard" in html_res.text

        # Test HTML export via /api/reports/{scan_id}/html
        report_html_res = client.get(f"/api/reports/{scan_id}/html")
        assert report_html_res.status_code == 200
        assert "text/html" in report_html_res.headers["content-type"]
        assert "<!DOCTYPE html>" in report_html_res.text
