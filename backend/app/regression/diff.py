"""Security Regression Diff & Fix Verification Engine for ShadowBoard.

Compares two scan runs (Baseline Commit A vs Current Commit B) to distinguish:
  - Newly discovered findings (regressions or new attack coverage)
  - Verified fixed findings (independently re-tested and proven blocked)
  - Unverified missing findings (disappeared due to adapter failure or omitted test — NOT counted as a fix!)
  - Recurrent regressions (findings that returned after a fix)
  - Observation coverage deltas
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class SecurityRegressionDiff:
    """Detailed differential comparison between two scan runs."""

    baseline_scan_id: Any
    current_scan_id: Any
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    verified_fixed_findings: List[Dict[str, Any]] = field(default_factory=list)
    unverified_missing_findings: List[Dict[str, Any]] = field(default_factory=list)
    recurrent_regressions: List[Dict[str, Any]] = field(default_factory=list)
    coverage_delta: Dict[str, Any] = field(default_factory=dict)
    ci_gate_passed: bool = True
    ci_gate_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "new_findings_count": len(self.new_findings),
            "new_findings": self.new_findings,
            "verified_fixed_count": len(self.verified_fixed_findings),
            "verified_fixed_findings": self.verified_fixed_findings,
            "unverified_missing_count": len(self.unverified_missing_findings),
            "unverified_missing_findings": self.unverified_missing_findings,
            "recurrent_regressions_count": len(self.recurrent_regressions),
            "recurrent_regressions": self.recurrent_regressions,
            "coverage_delta": self.coverage_delta,
            "ci_gate_passed": self.ci_gate_passed,
            "ci_gate_reason": self.ci_gate_reason,
        }


class RegressionDiffEngine:
    """Analyzes differences between baseline and candidate scans."""

    @classmethod
    def compare_scans(
        cls,
        baseline_findings: List[Dict[str, Any]],
        current_findings: List[Dict[str, Any]],
        executed_rule_ids_in_current: Optional[Set[str]] = None,
        baseline_scan_id: Any = "baseline",
        current_scan_id: Any = "current",
        strict_ci_gate: bool = True,
    ) -> SecurityRegressionDiff:
        executed_rules = executed_rule_ids_in_current or set()

        # Map findings by rule_id / policy_rule_id / finding_id
        def _get_rid(f: Dict[str, Any]) -> str:
            return str(f.get("rule_id") or f.get("policy_rule_id") or f.get("finding_id") or f.get("id") or "")

        baseline_by_rule = {_get_rid(f): f for f in baseline_findings if _get_rid(f)}
        current_by_rule = {_get_rid(f): f for f in current_findings if _get_rid(f)}

        new_findings: List[Dict[str, Any]] = []
        verified_fixed: List[Dict[str, Any]] = []
        unverified_missing: List[Dict[str, Any]] = []
        recurrent_regressions: List[Dict[str, Any]] = []

        # 1. Identify New Findings and Recurrent Findings
        for r_id, curr_f in current_by_rule.items():
            if r_id not in baseline_by_rule:
                new_findings.append(curr_f)
            else:
                # Existed in baseline
                base_f = baseline_by_rule[r_id]
                if base_f.get("status") == "FIXED" and curr_f.get("status") != "FIXED":
                    recurrent_regressions.append(curr_f)

        # 2. Check Baseline Findings that Disappeared
        for r_id, base_f in baseline_by_rule.items():
            if r_id not in current_by_rule:
                # Was the test actually executed in the current run?
                if executed_rules and r_id in executed_rules:
                    # Test was executed and returned no violation -> Verified Fix!
                    verified_fixed.append(base_f)
                else:
                    # Test was omitted or failed to execute -> Unverified missing!
                    unverified_missing.append({
                        **base_f,
                        "omission_reason": "Test was not re-executed or observation system failed in candidate run.",
                    })

        # 3. CI Gate Evaluation
        ci_passed = True
        gate_reasons: List[str] = []

        if strict_ci_gate:
            critical_high_new = [
                f for f in new_findings
                if f.get("severity") in ("CRITICAL", "HIGH")
            ]
            if critical_high_new:
                ci_passed = False
                gate_reasons.append(f"{len(critical_high_new)} new CRITICAL/HIGH security findings detected.")

            if recurrent_regressions:
                ci_passed = False
                gate_reasons.append(f"{len(recurrent_regressions)} recurrent regressions detected.")

        if not gate_reasons:
            gate_reasons.append("All regression checks passed. No new critical findings.")

        return SecurityRegressionDiff(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            new_findings=new_findings,
            verified_fixed_findings=verified_fixed,
            unverified_missing_findings=unverified_missing,
            recurrent_regressions=recurrent_regressions,
            coverage_delta={
                "baseline_findings": len(baseline_findings),
                "current_findings": len(current_findings),
                "retested_rules_count": len(executed_rules),
            },
            ci_gate_passed=ci_passed,
            ci_gate_reason=" | ".join(gate_reasons),
        )
