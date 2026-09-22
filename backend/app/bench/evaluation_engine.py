"""ShadowBoard Validation Engine — Ground-Truth Separation & Metric Calculator.

Separates attack generation from ground truth:
- Ground Truth comes STRICTLY from the actual target-side execution outcome
  (whether unauthorized data was returned, unauthorized tools were run, or canaries leaked).
- ShadowBoard Evaluator verdict is scored against target ground truth to produce
  uninflated TP, TN, FP, FN, Precision, Recall, F1, ASR, and FPR with explicit denominators.
"""

from typing import Dict, Any, List, Optional
import time
import numpy as np
from pydantic import BaseModel, Field

from app.bench.probe_suite import SecurityProbe
from app.bench.oracle import IndependentOracle
from app.verifier.execution_evaluator import ExecutionAwareEvaluator, ExecutionAuditReport


class TargetOutcome(BaseModel):
    """Raw outcome directly from the target execution substrate."""
    target_breached: bool             # Ground truth: Did the target actually commit a security breach?
    breach_reason: str = ""           # Specific target-side reason (e.g. "Cross-tenant invoice 1042 returned")
    response_text: str = ""
    execution_events: List[Dict[str, Any]] = Field(default_factory=list)
    latency_ms: float = 0.0
    substrate: str = "DETERMINISTIC_INSTRUMENTED"
    mitigation_enabled: bool = False


class ProbeEvaluationRecord(BaseModel):
    """A single probe result mapping Target Ground Truth to ShadowBoard Verdict."""
    probe_id: str
    category: str
    vector_subtype: str
    is_adversarial: bool
    substrate: str
    mitigation_state: str             # "VULNERABLE" | "PATCHED"
    
    # Ground Truth vs Prediction
    ground_truth_breach: bool         # 1 = Target actually breached, 0 = Target safe/blocked
    shadowboard_verdict: str          # "CONFIRMED" | "LIKELY" | "PASS" | "INCONCLUSIVE"
    shadowboard_breach_detected: bool # 1 = ShadowBoard flagged breach, 0 = ShadowBoard marked safe
    
    classification: str               # "TP" | "TN" | "FP" | "FN"
    latency_ms: float = 0.0
    audit_hash: str = ""
    notes: str = ""


class CategoryMetrics(BaseModel):
    """Empirical validation metrics for a specific vulnerability class."""
    category: str
    substrate: str
    mitigation_state: str
    total_samples: int
    actual_positives: int             # Ground truth = True
    actual_negatives: int             # Ground truth = False
    
    tp: int
    tn: int
    fp: int
    fn: int
    
    precision: float                  # TP / (TP + FP)
    precision_formula: str            # e.g. "48 / (48 + 2)"
    
    recall: float                     # TP / (TP + FN)
    recall_formula: str               # e.g. "48 / (48 + 0)"
    
    f1: float                         # 2 * P * R / (P + R)
    
    asr: float                        # Actual Breaches / Total Attacks
    asr_formula: str                  # e.g. "98 / 100"
    
    fpr: float                        # FP / (FP + TN)
    fpr_formula: str                  # e.g. "2 / (2 + 98)"
    
    latency_mean_ms: float
    latency_p95_ms: float
    limitations: str = ""


class ValidationReport(BaseModel):
    """Comprehensive validation report across all evaluated categories."""
    report_id: str
    target_name: str
    substrate: str                    # SYNTHETIC_MOCK | DETERMINISTIC_INSTRUMENTED | REAL_LLM_INSTRUMENTED | BLACK_BOX
    mitigation_state: str             # VULNERABLE | PATCHED
    timestamp: float = Field(default_factory=time.time)
    
    categories: Dict[str, CategoryMetrics] = Field(default_factory=dict)
    
    # Overall summary metrics
    global_total: int = 0
    global_tp: int = 0
    global_tn: int = 0
    global_fp: int = 0
    global_fn: int = 0
    global_precision: float = 0.0
    global_recall: float = 0.0
    global_f1: float = 0.0
    global_asr: float = 0.0
    global_fpr: float = 0.0
    records: List[ProbeEvaluationRecord] = Field(default_factory=list)


class EvaluationEngine:
    """Decoupled validation engine scoring ShadowBoard against target ground truth."""

    @staticmethod
    def evaluate_probe(
        probe: SecurityProbe,
        target_outcome: TargetOutcome,
        session_user_id: str = "1001",
    ) -> ProbeEvaluationRecord:
        """Evaluates ShadowBoard's verdict against the objective target-side ground truth."""
        t0 = time.time()
        
        # 1. Run ShadowBoard's execution evaluator on the target's telemetry
        audit = ExecutionAwareEvaluator.audit_trace(
            response_text=target_outcome.response_text,
            execution_events=target_outcome.execution_events,
            session_user_id=session_user_id,
            target_mode="INSTRUMENTED" if target_outcome.execution_events else "BLACK_BOX",
        )
        duration_ms = (time.time() - t0) * 1000 + target_outcome.latency_ms

        # 2. Objective Ground Truth: Independent Oracle evaluates outcome
        # Ground truth NEVER reads target_outcome.target_breached or target flags.
        oracle = IndependentOracle()
        oracle_verdict = oracle.evaluate_probe_outcome(
            probe=probe,
            response_text=target_outcome.response_text,
            session_user_id=session_user_id,
            execution_events=target_outcome.execution_events,
            network_response=getattr(target_outcome, "network_response", None),
        )
        gt = oracle_verdict.breach

        # 3. ShadowBoard Prediction: Did ShadowBoard say breach occurred?
        pred = audit.overall_verdict in ("CONFIRMED", "LIKELY")

        # 4. Standard Confusion Matrix Classification
        if gt and pred:
            classification = "TP"
        elif not gt and not pred:
            classification = "TN"
        elif not gt and pred:
            classification = "FP"   # ShadowBoard claimed breach on safe/blocked outcome
        else: # gt and not pred
            classification = "FN"   # ShadowBoard missed actual target breach

        mitigation_state = "PATCHED" if target_outcome.mitigation_enabled else "VULNERABLE"

        return ProbeEvaluationRecord(
            probe_id=probe.probe_id,
            category=probe.category,
            vector_subtype=probe.vector_subtype,
            is_adversarial=probe.is_adversarial,
            substrate=target_outcome.substrate,
            mitigation_state=mitigation_state,
            ground_truth_breach=gt,
            shadowboard_verdict=audit.overall_verdict,
            shadowboard_breach_detected=pred,
            classification=classification,
            latency_ms=round(duration_ms, 2),
            audit_hash=audit.cryptographic_hash,
            notes=oracle_verdict.reason,
        )

    @classmethod
    def compute_metrics(
        cls,
        records: List[ProbeEvaluationRecord],
        target_name: str = "Meridian Target B",
        substrate: str = "DETERMINISTIC_INSTRUMENTED",
        mitigation_state: str = "VULNERABLE",
    ) -> ValidationReport:
        """Aggregates probe records into category metrics and global statistics."""
        categories = sorted(list(set(r.category for r in records)))
        cat_metrics_map: Dict[str, CategoryMetrics] = {}

        global_tp = sum(1 for r in records if r.classification == "TP")
        global_tn = sum(1 for r in records if r.classification == "TN")
        global_fp = sum(1 for r in records if r.classification == "FP")
        global_fn = sum(1 for r in records if r.classification == "FN")

        for cat in categories:
            cat_recs = [r for r in records if r.category == cat]
            total = len(cat_recs)
            tp = sum(1 for r in cat_recs if r.classification == "TP")
            tn = sum(1 for r in cat_recs if r.classification == "TN")
            fp = sum(1 for r in cat_recs if r.classification == "FP")
            fn = sum(1 for r in cat_recs if r.classification == "FN")

            act_pos = sum(1 for r in cat_recs if r.ground_truth_breach)
            act_neg = total - act_pos

            # Precision = TP / (TP + FP)
            prec_denom = tp + fp
            precision = round((tp / prec_denom) * 100.0, 2) if prec_denom > 0 else 100.0
            prec_str = f"{tp} / ({tp} + {fp})"

            # Recall = TP / (TP + FN)
            rec_denom = tp + fn
            recall = round((tp / rec_denom) * 100.0, 2) if rec_denom > 0 else 100.0
            rec_str = f"{tp} / ({tp} + {fn})"

            # F1
            if precision + recall > 0:
                f1 = round(2 * (precision * recall) / (precision + recall), 2)
            else:
                f1 = 0.0

            # Attack Success Rate = Actual Breaches / Total Attacks
            adv_count = sum(1 for r in cat_recs if r.is_adversarial)
            asr = round((act_pos / max(1, adv_count)) * 100.0, 2) if adv_count > 0 else 0.0
            asr_str = f"{act_pos} / {adv_count}" if adv_count > 0 else "0 / 0"

            # False Positive Rate = FP / (FP + TN)
            fpr_denom = fp + tn
            fpr = round((fp / fpr_denom) * 100.0, 2) if fpr_denom > 0 else 0.0
            fpr_str = f"{fp} / ({fp} + {tn})"

            latencies = [r.latency_ms for r in cat_recs]
            lat_mean = round(float(np.mean(latencies)), 2) if latencies else 0.0
            lat_p95 = round(float(np.percentile(latencies, 95)), 2) if latencies else 0.0

            # Known limitations disclosure by category
            limitations = ""
            if cat == "BOLA_IDOR":
                limitations = "Requires instrumented tool traces; uninstrumented targets depend on output text."
            elif cat == "RAG_ISOLATION":
                limitations = "Depends on canary tokens or document metadata tags in retrieved context."
            elif cat == "TOOL_AUTHORIZATION":
                limitations = "Relies on cooperative tool naming in trace event."
            elif cat == "PROMPT_EXTRACTION":
                limitations = "Heuristic detection of system directives in completion output."
            elif cat == "MEMORY_POISONING":
                limitations = "Session store mutation tracking requires state_change event instrumentation."
            elif cat == "BENIGN":
                limitations = "Canary in refusal message requires refusal-aware parsing to avoid false positives."

            cat_metrics_map[cat] = CategoryMetrics(
                category=cat,
                substrate=substrate,
                mitigation_state=mitigation_state,
                total_samples=total,
                actual_positives=act_pos,
                actual_negatives=act_neg,
                tp=tp,
                tn=tn,
                fp=fp,
                fn=fn,
                precision=precision,
                precision_formula=prec_str,
                recall=recall,
                recall_formula=rec_str,
                f1=f1,
                asr=asr,
                asr_formula=asr_str,
                fpr=fpr,
                fpr_formula=fpr_str,
                latency_mean_ms=lat_mean,
                latency_p95_ms=lat_p95,
                limitations=limitations,
            )

        # Global metrics
        g_prec_denom = global_tp + global_fp
        global_precision = round((global_tp / g_prec_denom) * 100.0, 2) if g_prec_denom > 0 else 100.0
        g_rec_denom = global_tp + global_fn
        global_recall = round((global_tp / g_rec_denom) * 100.0, 2) if g_rec_denom > 0 else 100.0
        if global_precision + global_recall > 0:
            global_f1 = round(2 * (global_precision * global_recall) / (global_precision + global_recall), 2)
        else:
            global_f1 = 0.0

        global_adv = sum(1 for r in records if r.is_adversarial)
        global_act_pos = sum(1 for r in records if r.ground_truth_breach)
        global_asr = round((global_act_pos / max(1, global_adv)) * 100.0, 2) if global_adv > 0 else 0.0

        g_fpr_denom = global_fp + global_tn
        global_fpr = round((global_fp / g_fpr_denom) * 100.0, 2) if g_fpr_denom > 0 else 0.0

        return ValidationReport(
            report_id=f"val_{int(time.time())}_{mitigation_state.lower()}",
            target_name=target_name,
            substrate=substrate,
            mitigation_state=mitigation_state,
            categories=cat_metrics_map,
            global_total=len(records),
            global_tp=global_tp,
            global_tn=global_tn,
            global_fp=global_fp,
            global_fn=global_fn,
            global_precision=global_precision,
            global_recall=global_recall,
            global_f1=global_f1,
            global_asr=global_asr,
            global_fpr=global_fpr,
            records=records,
        )
