"""Security Regression Replay Engine.

When a finding is CONFIRMED, saves the exact exploit sequence.
After a fix is deployed, replays the SAME sequence to verify regression.
"""

import json
from typing import Dict, Any, Optional, List
import httpx
from app.verifier.engine import master_verifier


class RegressionReplayEngine:
    """Save and replay exact exploit sequences for regression testing."""

    @staticmethod
    def build_exploit_sequence(finding_result: Dict[str, Any]) -> str:
        """Extract the minimal exploit sequence from a confirmed finding."""
        attempts = finding_result.get("attempts", [])
        sequence = []
        for attempt in attempts:
            sequence.append({
                "turn": attempt.get("turn_number"),
                "strategy": attempt.get("strategy"),
                "prompt": attempt.get("prompt_text"),
                "expected_outcome": attempt.get("stance_tag"),
            })
        return json.dumps(sequence, indent=2)

    @staticmethod
    async def replay_exploit(
        exploit_sequence_json: str,
        target_base_url: str,
        rule_dict: Dict[str, Any],
        scan_mode: str = "INSTRUMENTED",
        target_capabilities: Optional[Dict[str, Any]] = None,
        client: Optional[httpx.AsyncClient] = None,
        session_user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Replay a saved exploit sequence against the target.
        
        Returns comparison of original vs current result.
        """
        from app.schemas.policy import PolicyRule
        
        sequence = json.loads(exploit_sequence_json)
        rule = PolicyRule(**rule_dict)
        session_uid = session_user_id or "session_replay_auth"
        
        replay_results = []
        
        for step in sequence:
            prompt_text = step["prompt"]
            response_text = ""
            execution_events = []
            
            try:
                if client:
                    resp = await client.post(
                        f"{target_base_url}/chat",
                        json={"messages": [{"role": "user", "content": prompt_text}]},
                    )
                else:
                    async with httpx.AsyncClient(timeout=15.0) as c:
                        resp = await c.post(
                            f"{target_base_url}/chat",
                            json={"messages": [{"role": "user", "content": prompt_text}]},
                        )
                if resp.status_code == 200:
                    body = resp.json()
                    response_text = body.get("response_text", "")
                    if scan_mode == "INSTRUMENTED":
                        trace = body.get("execution_trace", {})
                        raw_events = trace.get("events", [])
                        for ev in raw_events:
                            if isinstance(ev, dict) and "event_type" in ev:
                                ev["source"] = "target"
                                execution_events.append(ev)
            except Exception as err:
                response_text = f"Connection error: {err}"

            # Verify this step
            verification = master_verifier.verify(
                rule=rule,
                response_text=response_text,
                execution_events=execution_events,
                attack_prompt=prompt_text,
                session_user_id=session_uid,
                target_capabilities=target_capabilities,
            )
            
            replay_results.append({
                "turn": step["turn"],
                "strategy": step["strategy"],
                "original_outcome": step["expected_outcome"],
                "replay_response": response_text[:500],
                "replay_verdict": verification["status"],
                "replay_attack_outcome": verification.get("attack_outcome", "INCONCLUSIVE"),
            })

        # Determine regression status
        any_confirmed = any(r["replay_verdict"] == "CONFIRMED" for r in replay_results)
        
        return {
            "regression_status": "FAIL" if any_confirmed else "PASS",
            "message": (
                "Vulnerability still exploitable — fix did not hold."
                if any_confirmed
                else "Exploit sequence no longer succeeds — fix verified."
            ),
            "replay_steps": replay_results,
        }


regression_engine = RegressionReplayEngine()
