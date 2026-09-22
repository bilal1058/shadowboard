"""Run the separately implemented local reference target through ShadowBoard."""

import json
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
TARGET = ROOT / "validation" / "reference_target" / "target_process.py"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.verifier.execution_evaluator import ExecutionAwareEvaluator
from app.verifier.observations import SecurityObservation


CASES = (
    {"request_id": "REF-001", "profile_key": "profile-amber", "subject_ref": "subject-north", "enforce_boundary": False},
    {"request_id": "REF-002", "profile_key": "profile-cobalt", "subject_ref": "subject-west", "enforce_boundary": True},
    {"request_id": "REF-003", "profile_key": "profile-cobalt", "subject_ref": "subject-north", "enforce_boundary": True},
    {"request_id": "REF-004", "profile_key": "profile-amber", "subject_ref": "subject-east", "enforce_boundary": True},
)


def run() -> dict:
    with tempfile.TemporaryDirectory(prefix="shadowboard-reference-") as temp_dir:
        audit_db = Path(temp_dir) / "target-audit.sqlite3"
        target_outputs = []
        for case in CASES:
            payload = dict(case, audit_db=str(audit_db))
            result = subprocess.run(
                [sys.executable, str(TARGET)],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                check=True,
                cwd=str(ROOT),
            )
            target_outputs.append(json.loads(result.stdout))

        db = sqlite3.connect(audit_db)
        rows = db.execute(
            "SELECT request_id, subject_ref, resource_owner, profile_key, authorization, rows_returned "
            "FROM access_audit ORDER BY request_id"
        ).fetchall()
        db.close()

    records = []
    for case, output, row in zip(CASES, target_outputs, rows):
        request_id, subject_ref, resource_owner, profile_key, authorization, rows_returned = row
        observed_breach = (
            subject_ref != resource_owner
            and authorization == "allowed"
            and rows_returned > 0
        )
        audit = ExecutionAwareEvaluator.audit_observations([
            SecurityObservation(
                principal=subject_ref,
                resource_owner=resource_owner,
                resource=profile_key,
                action="read",
                authorization=authorization,
                result="returned" if rows_returned else "blocked",
                evidence={"source": "reference_target_sqlite_audit", "request_id": request_id},
            )
        ])
        predicted = audit.overall_verdict in ("CONFIRMED", "LIKELY")
        classification = (
            "TP" if observed_breach and predicted else
            "TN" if not observed_breach and not predicted else
            "FP" if not observed_breach and predicted else
            "FN"
        )
        records.append({
            "request_id": request_id,
            "target_output_status": output["status"],
            "ground_truth_breach": observed_breach,
            "shadowboard_verdict": audit.overall_verdict,
            "classification": classification,
        })

    counts = {key: sum(item["classification"] == key for item in records) for key in ("TP", "TN", "FP", "FN")}
    return {
        "suite": "reference_target_v1",
        "target": "standalone reference_target process",
        "target_imports_shadowboard": False,
        "truth_source": "reference_target_sqlite_audit_read_by_parent",
        "evaluator_input_excludes_ground_truth": True,
        "total": len(records),
        **{key.lower(): value for key, value in counts.items()},
        "records": records,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
