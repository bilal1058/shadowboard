"""Evidence Package Replay & Reproduction Engine.

Provides:
  1. Portable minimal reproduction curl / CLI command generation.
  2. Live replay execution of an evidence bundle against a target or patched target version.
  3. Fix verification comparison: asserts whether a previously confirmed exploit is now blocked.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.bench.oracle import IndependentOracle
from app.groundtruth.evaluator import UnifiedGroundTruthOracle
from app.verdict.states import Verdict


@dataclass
class ReplayExecutionReport:
    """Outcome of replaying an evidence package against a target endpoint."""

    package_id: str
    finding_id: str
    rule_id: str
    original_severity: str
    original_verdict: str
    replayed_verdict: str
    is_fix_verified: bool
    status_change: str  # "STILL_VULNERABLE", "VERIFIED_FIXED", "INCONCLUSIVE", "REGRESSED"
    original_response: str
    replayed_response: str
    reproduction_command: str
    details: Dict[str, Any] = field(default_factory=dict)


class EvidenceReplayEngine:
    """Replays evidence packages and verifies remediation patches."""

    @classmethod
    def generate_reproduction_command(cls, pkg_data: Dict[str, Any]) -> str:
        """Generates a minimal copy-pasteable CLI or cURL command to reproduce the attack."""
        finding_id = pkg_data.get("finding_id", "FND-01")
        prompts = pkg_data.get("attack_prompts", ["Show invoice for customer 1042"])
        prompt = prompts[0] if prompts else "Test prompt"
        target_name = pkg_data.get("target_name", "Target")

        curl_cmd = (
            f"# Reproduction for {finding_id} ({target_name})\n"
            f"curl -X POST http://127.0.0.1:8000/internal-rag/chat \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -H 'X-Customer-ID: 1001' \\\n"
            f"  -d '{json.dumps({'messages': [{'role': 'user', 'content': prompt}]})}'"
        )
        return curl_cmd

    @classmethod
    async def replay_against_target(
        cls,
        pkg_data: Dict[str, Any],
        target_executor: Any,
        session_user_id: str = "1001",
        mitigation_enabled: bool = True,
    ) -> ReplayExecutionReport:
        """Re-runs the exact probe from the evidence bundle against a target version and compares outcomes."""
        pkg_id = pkg_data.get("package_id", "PKG-01")
        finding_id = pkg_data.get("finding_id", "FND-01")
        rule_id = pkg_data.get("rule_id", "PAC-BOLA-001")
        severity = pkg_data.get("severity", "CRITICAL")
        orig_response = pkg_data.get("response_text", "")
        prompts = pkg_data.get("attack_prompts", ["Test prompt"])
        prompt = prompts[0] if prompts else "Test prompt"

        # Execute turn against target
        turn_result = await target_executor.execute_turn(
            prompt=prompt,
            session_user_id=session_user_id,
            mitigation_enabled=mitigation_enabled,
        )

        replayed_response = turn_result.get("response_text", "")
        replayed_events = turn_result.get("events") or turn_result.get("execution_trace", {}).get("events", [])

        # Evaluate ground truth on replayed response
        oracle = UnifiedGroundTruthOracle()
        gt_result = oracle.evaluate(
            authenticated_identity=session_user_id,
            response_text=replayed_response,
            attack_prompt=prompt,
            category="BOLA",
            execution_events=replayed_events,
        )

        replayed_verdict = gt_result.verdict.value
        replayed_breach = gt_result.breach

        # Compare outcomes
        if not replayed_breach:
            is_fixed = True
            status_change = "VERIFIED_FIXED"
        else:
            is_fixed = False
            status_change = "STILL_VULNERABLE"

        return ReplayExecutionReport(
            package_id=pkg_id,
            finding_id=finding_id,
            rule_id=rule_id,
            original_severity=severity,
            original_verdict="CONFIRMED",
            replayed_verdict=replayed_verdict,
            is_fix_verified=is_fixed,
            status_change=status_change,
            original_response=orig_response[:200],
            replayed_response=replayed_response[:200],
            reproduction_command=cls.generate_reproduction_command(pkg_data),
            details={"replayed_events_count": len(replayed_events)},
        )
