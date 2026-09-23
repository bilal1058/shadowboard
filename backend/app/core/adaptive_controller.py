"""Adaptive Scan Controller — Orchestrates multi-turn attacks with isolated session state.

Core rules:
1. ShadowBoard must NEVER infer an execution event it did not receive from the target.
2. For BLACK_BOX mode: response text only. No tool/RAG/memory claims.
3. For INSTRUMENTED mode: response text + target-produced runtime events.
4. Strategy selection is CONSTRAINED: previous observation → FSM → allowed strategy ID.
5. Each objective gets isolated session state (no global mutable lists).
6. Every object carries the provenance chain: scan_id → target_id → objective_id → attempt_id → session_id.
"""

import httpx
import json
import uuid
from typing import Dict, Any, List, Optional
from app.core.FSM import FSMStanceClassifier
from app.verifier.engine import master_verifier
from app.schemas.policy import PolicyRule
from app.schemas.scan import ObservationRecord
from app.engines.injection import InjectionEngine
from app.engines.leakage import LeakageEngine
from app.engines.agency import AgencyEngine


class ObjectiveSession:
    """Isolated state for a single attack objective. No global mutable lists."""
    
    def __init__(self, scan_id: int, target_id: int, objective_id: str):
        self.scan_id = scan_id
        self.target_id = target_id
        self.objective_id = objective_id
        self.session_id = f"sess_{scan_id}_{objective_id}_{uuid.uuid4().hex[:8]}"
        self.observations: List[ObservationRecord] = []
        self.attempts: List[Dict[str, Any]] = []

    def record_observation(self, observation: ObservationRecord):
        self.observations.append(observation)

    def get_last_observation(self) -> Optional[ObservationRecord]:
        return self.observations[-1] if self.observations else None


class AdaptiveScanController:
    """
    Orchestrates multi-turn attack objectives against target application.
    Executes up to 3 turns per objective, pivots via FSM Stance Classifier,
    and submits traces to Policy Assertion Engine.
    """

    def __init__(
        self,
        target_base_url: str,
        scan_mode: str = "INSTRUMENTED",
        target_capabilities: Optional[Dict[str, Any]] = None,
        scan_id: int = 0,
        target_id: int = 0,
        client: Optional[httpx.AsyncClient] = None,
        mitigation_enabled: bool = False,
    ):
        self.target_base_url = target_base_url
        self.scan_mode = scan_mode
        self.target_capabilities = target_capabilities or {}
        self.scan_id = scan_id
        self.target_id = target_id
        self.client = client
        self.mitigation_enabled = mitigation_enabled
        self.fsm = FSMStanceClassifier()

        self.engines = {
            "injection": InjectionEngine(),
            "leakage": LeakageEngine(),
            "agency": AgencyEngine(),
        }

    async def execute_objective(
        self,
        family: str,
        rule: PolicyRule,
        max_turns: int = 3,
        on_turn_completed: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Execute a multi-turn attack for a single policy rule.
        
        Returns the three-dimensional result:
          status (security_verdict), attack_outcome, evidence_status,
          evidence_strength, evidence, evidence_hash, remediation, attempts
        """
        engine = self.engines.get(family)
        if not engine:
            return self._error_result(f"Unknown attack family: {family}")

        # Isolated session per objective
        session = ObjectiveSession(
            scan_id=self.scan_id,
            target_id=self.target_id,
            objective_id=rule.id,
        )

        # Start with the first strategy
        current_strategy = engine.get_initial_strategy()

        final_result = {
            "status": "PASS",
            "attack_outcome": "INCONCLUSIVE",
            "evidence_status": "INSUFFICIENT",
            "severity": "LOW",
            "evidence_strength": 0.0,
            "confidence": 0.0,  # Deprecated compatibility alias.
            "evidence": {},
            "evidence_hash": "",
            "remediation": "No policy violation detected.",
            "attempts": [],
        }

        for turn in range(1, max_turns + 1):
            # 1. Generate attack prompt using current strategy
            prompt_text = engine.build_prompt(
                rule, current_strategy, session.attempts,
                observation=session.get_last_observation(),
            )

            # 2. Send to target, collect ONLY events from target response
            target_response_text, execution_events = await self._interact_with_target(
                prompt_text, session
            )

            # 3. Classify stance
            stance_eval = await self.fsm.evaluate_stance(
                prompt_text, target_response_text, execution_events
            )

            # 4. Get constrained next strategy from FSM
            observation = self.fsm.get_next_strategy(
                family, stance_eval.stance, current_strategy
            )
            observation.refusal_strength = stance_eval.confidence
            observation.rag_retrieved = any(
                e.get("event_type") == "rag_retrieval" for e in execution_events
            )
            observation.tool_called = any(
                e.get("event_type") == "tool_call" for e in execution_events
            )
            session.record_observation(observation)

            # 5. Run verifier with full context
            verification = master_verifier.verify(
                rule=rule,
                response_text=target_response_text,
                execution_events=execution_events,
                attack_prompt=prompt_text,
                session_user_id="1001",
                target_mode=self.scan_mode,
                target_capabilities=self.target_capabilities,
            )

            # 6. Record attempt with provenance
            attempt_data = {
                "turn_number": turn,
                "strategy": current_strategy,
                "prompt_text": prompt_text,
                "response_text": target_response_text,
                "stance_tag": stance_eval.stance,
                "stance_reason": stance_eval.reason,
                "stance_confidence": stance_eval.confidence,
                "next_strategy": observation.decision,
                "observation": {
                    "previous_strategy": observation.previous_strategy,
                    "attack_outcome": observation.attack_outcome,
                    "decision": observation.decision,
                    "decision_reason": observation.decision_reason,
                    "refusal_strength": observation.refusal_strength,
                    "rag_retrieved": observation.rag_retrieved,
                    "tool_called": observation.tool_called,
                },
                "execution_events": execution_events,
                # Provenance chain
                "scan_id": session.scan_id,
                "target_id": session.target_id,
                "session_id": session.session_id,
            }
            session.attempts.append(attempt_data)

            # Invoke real-time callback if provided
            if on_turn_completed:
                try:
                    await on_turn_completed(turn, attempt_data)
                except Exception:
                    pass

            # 7. Check if finding is established
            if verification["status"] in ("CONFIRMED", "LIKELY"):
                final_result = {
                    "status": verification["status"],
                    "attack_outcome": verification.get("attack_outcome", "COMPLIED"),
                    "evidence_status": verification.get("evidence_status", "SUFFICIENT"),
                    "severity": verification["severity"],
                    "evidence_strength": verification.get("evidence_strength", verification["confidence"]),
                    "confidence": verification["confidence"],  # Deprecated compatibility alias.
                    "evidence": verification["evidence"],
                    "evidence_hash": verification["evidence_hash"],
                    "remediation": verification["remediation"],
                    "attempts": session.attempts,
                }
                if max_turns <= 3:
                    return final_result

            # 8. Adaptive mutation on block / refusal:
            # Pivot to FSM-selected next strategy and continue battery!
            if turn < max_turns:
                current_strategy = observation.decision

        # Return best result from all turns
        final_result["attempts"] = session.attempts

        # If model defended and no confirmed finding was made
        if final_result["status"] == "PASS":
            has_refusal = any(
                a.get("stance_tag") == "REFUSED" for a in session.attempts
            )
            no_compliance = not any(
                a.get("stance_tag") == "COMPLIED" for a in session.attempts
            )
            if has_refusal and no_compliance and session.attempts:
                final_result["attack_outcome"] = "BLOCKED"
                final_result["evidence_status"] = "SUFFICIENT"

        return final_result

    async def _interact_with_target(
        self,
        prompt_text: str,
        session: ObjectiveSession,
    ) -> tuple:
        """Send probe to target and collect ONLY target-produced events.
        
        CRITICAL: execution_events come FROM the target's response.
        ShadowBoard NEVER constructs tool_call, rag_retrieval, or memory events.
        
        For BLACK_BOX targets: only response_text is used. execution_events = [].
        For INSTRUMENTED targets: events from target's execution_trace.events.
        """
        target_response_text = ""
        execution_events = []

        headers = {
            "x-customer-id": "1001",
            "x-session-id": session.session_id,
            "x-mitigation-enabled": "true" if self.mitigation_enabled else "false",
        }

        try:
            payload = {
                "messages": [{"role": "user", "content": prompt_text}],
                "prompt": prompt_text,
                "session_user_id": "1001",
            }
            if self.client:
                resp = await self.client.post(
                    f"{self.target_base_url}/chat",
                    json=payload,
                    headers=headers,
                )
            else:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(
                        f"{self.target_base_url}/chat",
                        json=payload,
                        headers=headers,
                    )
            if resp.status_code == 200:
                body = resp.json()
                target_response_text = body.get("response_text", "") or body.get("response", "")

                # ONLY extract events for INSTRUMENTED mode
                if self.scan_mode == "INSTRUMENTED":
                    trace = body.get("execution_trace", {})
                    raw_events = trace.get("events", []) if isinstance(trace, dict) else []
                    if not raw_events:
                        raw_events = body.get("execution_events", [])
                    # Validate each event has required structure
                    for ev in raw_events:
                        if (
                            isinstance(ev, dict)
                            and "event_type" in ev
                            and "event_data" in ev
                        ):
                            # Tag source as 'target' — scanner never produces events
                            ev["source"] = "target"
                            execution_events.append(ev)
                # BLACK_BOX: execution_events stays empty
            else:
                target_response_text = f"HTTP error: {resp.status_code}"
        except Exception as err:
            target_response_text = f"Connection error: {str(err)}"

        return target_response_text, execution_events


    @staticmethod
    def _error_result(message: str) -> Dict[str, Any]:
        return {
            "status": "ERROR",
            "attack_outcome": "ERROR",
            "evidence_status": "NOT_AVAILABLE",
            "severity": "LOW",
            "evidence_strength": 0.0,
            "confidence": 0.0,  # Deprecated compatibility alias.
            "evidence": {"error": message},
            "evidence_hash": "",
            "remediation": "",
            "attempts": [],
        }
