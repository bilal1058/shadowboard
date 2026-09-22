"""Continuous AI Security Regression Testing Engine.

Enables organizations to establish security baselines, rerun ShadowBoard on AI updates,
and automatically verify if vulnerabilities disappeared or if regressions were introduced.
Supports CI/CD pass/fail gates.
"""

from typing import Dict, Any, List, Optional
import hashlib
import json
import re
import time
from pydantic import BaseModel, Field


class FindingSnapshot(BaseModel):
    rule_id: str
    rule_name: str = ""
    status: str              # CONFIRMED | LIKELY | INCONCLUSIVE | PASS
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    owasp_category: str = ""
    evidence_hash: str = ""
    remediation: str = ""
    fingerprint: str = ""


def finding_fingerprint(finding: Dict[str, Any], target_id: int) -> str:
    """Create semantic identity without IDs, wording, evidence, or timestamps."""
    security_property = finding.get("security_property") or finding.get("application_security_class")
    if not security_property:
        security_property = finding.get("owasp_category") or finding.get("rule_name") or finding.get("rule_id") or "unknown"
    normalized = {
        "target_id": target_id,
        "security_property": re.sub(r"[^a-z0-9]+", "_", str(security_property).lower()).strip("_"),
        "resource": str(finding.get("resource", "")).lower(),
        "action": str(finding.get("action", "")).lower(),
        "principal_resource_relation": str(finding.get("principal_resource_relation", "")).lower(),
    }
    return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode("utf-8")).hexdigest()


class SecurityBaseline(BaseModel):
    baseline_id: str
    target_id: int
    scan_id: int
    created_at: float = Field(default_factory=time.time)
    risk_score: int
    risk_grade: str
    findings: Dict[str, FindingSnapshot] = Field(default_factory=dict)


class CIGatePolicy(BaseModel):
    fail_on_critical: bool = True
    fail_on_new_vulnerabilities: bool = True
    max_allowed_confirmed: int = 0
    min_security_score: int = 75


class RegressionComparison(BaseModel):
    target_id: int
    baseline_scan_id: int
    current_scan_id: int
    baseline_score: int
    current_score: int
    score_delta: int
    baseline_grade: str
    current_grade: str

    resolved_vulnerabilities: List[FindingSnapshot] = []
    new_vulnerabilities: List[FindingSnapshot] = []
    persisting_vulnerabilities: List[FindingSnapshot] = []
    unchanged_passed: List[FindingSnapshot] = []

    ci_gate_status: str       # "PASSED" | "FAILED"
    ci_gate_reasons: List[str] = []
    summary_narrative: str = ""


class ContinuousRegressionEngine:
    """Manages baselines, compares successive scans, and evaluates CI/CD security gates."""

    @staticmethod
    def create_baseline(
        target_id: int,
        scan_id: int,
        risk_score: int,
        risk_grade: str,
        findings_list: List[Dict[str, Any]],
    ) -> SecurityBaseline:
        """Saves a completed scan run as a reference baseline."""
        findings_map = {}
        for f in findings_list:
            rule_id = f.get("finding_id") or f.get("rule_id") or f.get("id") or "RULE-UNKNOWN"
            fingerprint = finding_fingerprint(f, target_id)
            findings_map[fingerprint] = FindingSnapshot(
                rule_id=rule_id,
                rule_name=f.get("rule_name", rule_id),
                status=f.get("status", "PASS"),
                severity=f.get("severity", "MEDIUM"),
                owasp_category=f.get("owasp_category", ""),
                evidence_hash=f.get("evidence_hash", ""),
                remediation=f.get("remediation", ""),
                fingerprint=fingerprint,
            )

        return SecurityBaseline(
            baseline_id=f"base_tgt{target_id}_scan{scan_id}",
            target_id=target_id,
            scan_id=scan_id,
            risk_score=risk_score,
            risk_grade=risk_grade,
            findings=findings_map,
        )

    @staticmethod
    def compare_against_baseline(
        baseline: SecurityBaseline,
        current_scan_id: int,
        current_score: int,
        current_grade: str,
        current_findings: List[Dict[str, Any]],
        gate_policy: Optional[CIGatePolicy] = None,
    ) -> RegressionComparison:
        """Computes diff between baseline and latest scan."""
        policy = gate_policy or CIGatePolicy()
        curr_map: Dict[str, FindingSnapshot] = {}
        for f in current_findings:
            rule_id = f.get("finding_id") or f.get("rule_id") or f.get("id") or "RULE-UNKNOWN"
            fingerprint = finding_fingerprint(f, baseline.target_id)
            curr_map[fingerprint] = FindingSnapshot(
                rule_id=rule_id,
                rule_name=f.get("rule_name", rule_id),
                status=f.get("status", "PASS"),
                severity=f.get("severity", "MEDIUM"),
                owasp_category=f.get("owasp_category", ""),
                evidence_hash=f.get("evidence_hash", ""),
                remediation=f.get("remediation", ""),
                fingerprint=fingerprint,
            )

        resolved: List[FindingSnapshot] = []
        new_vulns: List[FindingSnapshot] = []
        persisting: List[FindingSnapshot] = []
        passed: List[FindingSnapshot] = []

        all_rule_ids = set(baseline.findings.keys()).union(set(curr_map.keys()))

        for r_id in all_rule_ids:
            b_item = baseline.findings.get(r_id)
            c_item = curr_map.get(r_id)

            b_breach = (b_item is not None and b_item.status in ("CONFIRMED", "LIKELY"))
            c_breach = (c_item is not None and c_item.status in ("CONFIRMED", "LIKELY"))

            if b_breach and not c_breach:
                # Vulnerability was eliminated!
                resolved.append(b_item)
            elif not b_breach and c_breach:
                # New security regression introduced!
                new_vulns.append(c_item)
            elif b_breach and c_breach:
                # Still vulnerable
                persisting.append(c_item or b_item)
            else:
                if c_item:
                    passed.append(c_item)

        score_delta = current_score - baseline.risk_score

        # CI/CD Gate evaluation
        gate_reasons: List[str] = []
        ci_status = "PASSED"

        if policy.fail_on_critical:
            critical_curr = [v for v in (persisting + new_vulns) if v.severity == "CRITICAL"]
            if critical_curr:
                ci_status = "FAILED"
                gate_reasons.append(
                    f"Blocked: {len(critical_curr)} CRITICAL vulnerabilities detected ({', '.join(v.rule_id for v in critical_curr)})"
                )

        if policy.fail_on_new_vulnerabilities and new_vulns:
            ci_status = "FAILED"
            gate_reasons.append(
                f"Blocked: {len(new_vulns)} NEW security regression(s) introduced ({', '.join(v.rule_id for v in new_vulns)})"
            )

        confirmed_count = len(persisting) + len(new_vulns)
        if confirmed_count > policy.max_allowed_confirmed:
            ci_status = "FAILED"
            gate_reasons.append(
                f"Blocked: {confirmed_count} confirmed findings exceed threshold of {policy.max_allowed_confirmed}"
            )

        if current_score < policy.min_security_score:
            ci_status = "FAILED"
            gate_reasons.append(
                f"Blocked: Security score {current_score} is below minimum bar {policy.min_security_score}"
            )

        if not gate_reasons:
            gate_reasons.append("All security regression gates PASSED. Target application approved for deployment.")

        # Narrative summary
        if len(resolved) > 0 and len(new_vulns) == 0:
            narrative = f"SECURITY IMPROVEMENT: {len(resolved)} vulnerability(ies) successfully mitigated. Security score moved from {baseline.risk_score} ({baseline.risk_grade}) to {current_score} ({current_grade}) (+{score_delta} pts)."
        elif len(new_vulns) > 0:
            narrative = f"SECURITY REGRESSION: Fix or code update introduced {len(new_vulns)} new vulnerability(ies). Score changed by {score_delta} pts."
        elif len(persisting) > 0:
            narrative = f"UNCHANGED RISK: {len(persisting)} vulnerability(ies) persist. No new vulnerabilities detected."
        else:
            narrative = f"STABLE POSTURE: All tested objectives passed cleanly. Score: {current_score} ({current_grade})."

        return RegressionComparison(
            target_id=baseline.target_id,
            baseline_scan_id=baseline.scan_id,
            current_scan_id=current_scan_id,
            baseline_score=baseline.risk_score,
            current_score=current_score,
            score_delta=score_delta,
            baseline_grade=baseline.risk_grade,
            current_grade=current_grade,
            resolved_vulnerabilities=resolved,
            new_vulnerabilities=new_vulns,
            persisting_vulnerabilities=persisting,
            unchanged_passed=passed,
            ci_gate_status=ci_status,
            ci_gate_reasons=gate_reasons,
            summary_narrative=narrative,
        )
