from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Execution mode — determines what evidence ShadowBoard can use
# ---------------------------------------------------------------------------
ExecutionMode = Literal["BLACK_BOX", "INSTRUMENTED"]
# BLACK_BOX: response text only. ShadowBoard MUST NOT claim tool/RAG/memory events.
# INSTRUMENTED: response + actual runtime events from the target's execution_trace.


# ---------------------------------------------------------------------------
# Three-dimensional result model
# ---------------------------------------------------------------------------

# 1. Attack outcome: what the target did in response to the attack
AttackOutcome = Literal["BLOCKED", "COMPLIED", "PARTIAL", "INCONCLUSIVE", "ERROR"]

# 2. Security verdict: the policy-level conclusion
SecurityVerdict = Literal["CONFIRMED", "LIKELY", "INCONCLUSIVE", "PASS", "ERROR", "NOT_APPLICABLE"]

# 3. Evidence status: quality of the supporting evidence
EvidenceStatus = Literal["SUFFICIENT", "PARTIAL", "INSUFFICIENT", "NOT_AVAILABLE"]


# ---------------------------------------------------------------------------
# Taxonomy versioning
# ---------------------------------------------------------------------------
class TaxonomyReference(BaseModel):
    taxonomy: str = "OWASP"                # e.g. "OWASP", "MITRE_ATLAS"
    taxonomy_version: str = "2025"         # e.g. "2025", "2026"
    category_id: str = ""                  # e.g. "LLM01"
    category_name: str = ""                # e.g. "Prompt Injection"
    application_security_class: Optional[str] = None  # e.g. "BOLA/IDOR"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ScanCreateRequest(BaseModel):
    target_id: int
    scan_mode: ExecutionMode = "INSTRUMENTED"
    mitigation_enabled: bool = False


class TargetStanceEvaluation(BaseModel):
    stance: Literal["REFUSED", "PARTIAL", "COMPLIED", "EVASIVE"]
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)


class ObservationRecord(BaseModel):
    """Records what the FSM observed and why it chose the next strategy."""
    previous_strategy: str = ""
    attack_outcome: AttackOutcome = "INCONCLUSIVE"
    refusal_strength: Optional[float] = None
    policy_effect: bool = False
    rag_retrieved: bool = False
    tool_called: bool = False
    evidence_signals: List[str] = []
    decision: str = ""
    decision_reason: str = ""


class ExecutionEventSchema(BaseModel):
    event_type: Literal[
        "tool_call", "rag_retrieval", "memory_access",
        "output_filter_triggered", "authz_document_blocked",
        "db_operation", "network_egress", "state_change"
    ]
    event_data: Dict[str, Any]
    source: str = "target"  # "target" only — scanner never produces events


class AttemptRecordSchema(BaseModel):
    turn_number: int
    strategy: str
    prompt_text: str
    response_text: Optional[str] = None
    stance_tag: Optional[str] = None
    stance_reason: Optional[str] = None
    stance_confidence: Optional[float] = None
    next_strategy: Optional[str] = None
    observation: Optional[ObservationRecord] = None
    execution_events: List[ExecutionEventSchema] = []


class FindingSchema(BaseModel):
    finding_id: str
    owasp_category: str
    taxonomy: Optional[TaxonomyReference] = None
    application_security_class: Optional[str] = None
    status: SecurityVerdict
    attack_outcome: AttackOutcome = "INCONCLUSIVE"
    evidence_status: EvidenceStatus = "INSUFFICIENT"
    evidence_strength: float = Field(
        description="Heuristic evidence strength; not a calibrated probability."
    )
    confidence: Optional[float] = Field(
        default=None,
        description="Deprecated compatibility alias for evidence_strength; not a probability.",
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    evidence_json: Dict[str, Any]
    evidence_hash: str
    remediation: str


class ScanResultSummary(BaseModel):
    """Canonical scan result — the single source of truth."""
    scan_id: int
    objectives_tested: int = 0
    confirmed: int = 0
    likely: int = 0
    inconclusive: int = 0
    passed: int = 0
    errors: int = 0
    not_applicable: int = 0
    policy_coverage: float = 0.0  # fraction of applicable rules tested


class SSEScanEvent(BaseModel):
    type: Literal[
        "status_update", "objective_start", "objective_skipped",
        "attempt_complete", "objective_complete", "scan_complete", "error"
    ]
    scan_id: int
    data: Dict[str, Any]
