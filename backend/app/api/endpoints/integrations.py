"""API Router for Ecosystem Integrations (GitHub, GitLab, Slack, Jira)."""

from fastapi import APIRouter, HTTPException, Depends, Response
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import aiosqlite
import json

from app.db.session import get_db
from app.integrations import SARIFGenerator, JUnitGenerator, SlackAlertFormatter, JiraIssueFormatter

router = APIRouter(prefix="/integrations", tags=["Ecosystem Integrations"])


class SlackPreviewRequest(BaseModel):
    target_name: str
    scan_id: int
    risk_score: int
    risk_grade: str
    findings: List[Dict[str, Any]] = []


class JiraPreviewRequest(BaseModel):
    target_name: str
    finding: Dict[str, Any]
    project_key: str = "SEC"


@router.get("/sarif/{scan_id}")
async def export_scan_sarif(scan_id: int, db: aiosqlite.Connection = Depends(get_db)):
    """Exports findings as an OASIS SARIF 2.1.0 document for GitHub Code Scanning."""
    cursor = await db.execute(
        """
        SELECT s.id, COALESCE(t.name, 'Target #' || s.target_id), f.finding_id, f.owasp_category, f.status, f.severity, f.remediation, f.evidence_hash
        FROM scan_runs s
        LEFT JOIN targets t ON s.target_id = t.id
        LEFT JOIN findings f ON s.id = f.scan_id
        WHERE s.id = ?
        """,
        (scan_id,)
    )
    rows = await cursor.fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="Scan run not found")

    target_name = rows[0][1]
    findings = []
    for r in rows:
        if r[2]:  # Has finding_id
            findings.append({
                "finding_id": r[2],
                "rule_name": r[2],
                "owasp_category": r[3],
                "status": r[4],
                "severity": r[5],
                "remediation": r[6],
                "evidence_hash": r[7],
            })

    sarif = SARIFGenerator.generate_sarif(target_name=target_name, scan_id=scan_id, findings=findings)
    return sarif


@router.get("/junit/{scan_id}")
async def export_scan_junit(scan_id: int, db: aiosqlite.Connection = Depends(get_db)):
    """Exports scan results as JUnit XML for GitLab / Jenkins pipeline integration."""
    cursor = await db.execute(
        """
        SELECT s.id, COALESCE(t.name, 'Target #' || s.target_id), f.finding_id, f.owasp_category, f.status, f.severity, f.remediation, f.evidence_hash
        FROM scan_runs s
        LEFT JOIN targets t ON s.target_id = t.id
        LEFT JOIN findings f ON s.id = f.scan_id
        WHERE s.id = ?
        """,
        (scan_id,)
    )
    rows = await cursor.fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="Scan run not found")

    target_name = rows[0][1]
    findings = []
    for r in rows:
        if r[2]:
            findings.append({
                "finding_id": r[2],
                "rule_name": r[2],
                "owasp_category": r[3],
                "status": r[4],
                "severity": r[5],
                "remediation": r[6],
                "evidence_hash": r[7],
            })

    xml_content = JUnitGenerator.generate_junit_xml(target_name=target_name, scan_id=scan_id, findings=findings)
    return Response(content=xml_content, media_type="application/xml")


@router.post("/slack/preview")
def preview_slack_payload(request: SlackPreviewRequest):
    """Generates preview of Slack Block Kit notification payload."""
    return SlackAlertFormatter.format_scan_alert(
        target_name=request.target_name,
        scan_id=request.scan_id,
        risk_score=request.risk_score,
        risk_grade=request.risk_grade,
        findings=request.findings,
    )


@router.post("/jira/preview")
def preview_jira_payload(request: JiraPreviewRequest):
    """Generates preview of Jira Issue ticket creation payload."""
    return JiraIssueFormatter.format_jira_issue(
        target_name=request.target_name,
        finding=request.finding,
        project_key=request.project_key,
        evidence_hash=request.finding.get("evidence_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    )
