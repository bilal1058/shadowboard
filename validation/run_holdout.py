"""Run the frozen holdout without exposing labels to the evaluator.

Usage:
    python validation/run_holdout.py
    python validation/run_holdout.py --output validation/results/holdout.json
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.verifier.execution_evaluator import ExecutionAwareEvaluator
from app.verifier.observations import SecurityObservation
from validation.holdout.cases import HOLDOUT_CASES
from validation.holdout.independent_target import ObserverOwnedAuditJournal, UnfamiliarStatementTarget
from validation.holdout.observer import IndependentObserver


def run() -> dict:
    journal = ObserverOwnedAuditJournal()
    target = UnfamiliarStatementTarget(journal)
    observer = IndependentObserver(journal)
    records = []

    for case in HOLDOUT_CASES:
        target_result = target.execute(case)
        observed = observer.observe(case)
        audit = ExecutionAwareEvaluator.audit_observations(
            [
                SecurityObservation(
                    principal=observed.principal_ref,
                    resource_owner=observed.resource_owner,
                    resource=observed.evidence["resource_id"],
                    action=observed.action,
                    authorization=observed.authorization,
                    result=observed.result,
                    evidence=observed.evidence,
                )
            ],
            target_mode="OBSERVER",
        )
        predicted = audit.overall_verdict in ("CONFIRMED", "LIKELY")
        records.append(
            {
                "case_id": case.case_id,
                "ground_truth_breach": observed.breached,
                "shadowboard_verdict": audit.overall_verdict,
                "shadowboard_breach_detected": predicted,
                "classification": (
                    "TP" if observed.breached and predicted else
                    "TN" if not observed.breached and not predicted else
                    "FP" if not observed.breached and predicted else
                    "FN"
                ),
                "observer_evidence": observed.evidence,
                "observer_authorization": observed.authorization,
                "observer_result": observed.result,
            }
        )

    tp = sum(record["classification"] == "TP" for record in records)
    tn = sum(record["classification"] == "TN" for record in records)
    fp = sum(record["classification"] == "FP" for record in records)
    fn = sum(record["classification"] == "FN" for record in records)
    actual_positive = tp + fn
    actual_negative = tn + fp

    return {
        "suite": "holdout_v1",
        "target": "UnfamiliarStatementTarget",
        "truth_source": "observer_owned_audit_journal",
        "evaluator_input_excludes_ground_truth": True,
        "total": len(records),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision_percent": round(tp / max(1, tp + fp) * 100.0, 2),
        "recall_percent": round(tp / max(1, actual_positive) * 100.0, 2),
        "fpr_percent": round(fp / max(1, actual_negative) * 100.0, 2),
        "fnr_percent": round(fn / max(1, actual_positive) * 100.0, 2),
        "records": records,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    serialized = json.dumps(result, indent=2, sort_keys=True)
    print(serialized)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
