"""ShadowBoard Standardized Benchmark Runner & Artifact Generator.

Executes systematic evaluation matrices across vulnerable and mitigated targets,
calculates calibrated Wilson score confidence intervals, records telemetry and latencies,
and persists versioned, tamper-auditable JSON artifacts under backend/app/bench/results/.
"""

import os
import sys
import json
import time
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import argparse
import asyncio
import numpy as np

from app.bench.probe_suite import ProbeSuiteGenerator, SecurityProbe
from app.bench.target_substrates import DeterministicTargetExecutor, RealLLMToolAgent
from app.bench.evaluation_engine import EvaluationEngine, ProbeEvaluationRecord
from app.bench.wilson import wilson_score_interval, format_wilson_ci

RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def get_git_commit_sha() -> str:
    """Retrieves current Git commit SHA or returns fallback."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).parent,
            timeout=3,
        )
        return res.stdout.strip()
    except Exception:
        return "untracked_workspace"


def compute_probe_suite_hash(probes: List[SecurityProbe]) -> str:
    """Computes a deterministic SHA-256 fingerprint over the probe definitions."""
    canonical = []
    for p in sorted(probes, key=lambda x: x.probe_id):
        canonical.append({
            "probe_id": p.probe_id,
            "category": p.category,
            "vector_subtype": p.vector_subtype,
            "prompt": p.prompt,
            "session_user_id": p.session_user_id,
            "target_parameters": p.target_parameters,
            "is_adversarial": p.is_adversarial,
        })
    raw_bytes = json.dumps(canonical, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw_bytes).hexdigest()


async def execute_benchmark_suite(
    probes_per_class: int = 100,
    mitigation_enabled: bool = False,
    substrate: str = "DETERMINISTIC_INSTRUMENTED",
    model_name: Optional[str] = None,
    provider: str = "deterministic_local",
    probe_set_version: str = "v1.2.0",
) -> Dict[str, Any]:
    """Runs the benchmark suite and produces a complete, calibrated result artifact."""
    if model_name is None:
        model_name = os.getenv("TARGET_MODEL", "deterministic-oracle-v1")

    print(f"[*] Generating probe suite ({probes_per_class} per class)...")
    probes = ProbeSuiteGenerator.generate_full_validation_suite(probes_per_class=probes_per_class)
    config_hash = compute_probe_suite_hash(probes)
    git_sha = get_git_commit_sha()

    print(f"[*] Executing {len(probes)} probes on substrate={substrate} (mitigation={mitigation_enabled})...")
    records: List[ProbeEvaluationRecord] = []
    latencies: List[float] = []

    for idx, probe in enumerate(probes):
        t0 = time.time()
        if substrate == "REAL_LLM_INSTRUMENTED":
            agent = RealLLMToolAgent()
            outcome = await agent.execute_turn(
                prompt=probe.prompt,
                session_user_id=probe.session_user_id,
                mitigation_enabled=mitigation_enabled,
            )
        else:
            outcome = await DeterministicTargetExecutor.execute_probe(
                probe=probe,
                mitigation_enabled=mitigation_enabled,
            )
        duration_ms = (time.time() - t0) * 1000 + outcome.latency_ms
        latencies.append(duration_ms)

        rec = EvaluationEngine.evaluate_probe(
            probe=probe,
            target_outcome=outcome,
            session_user_id=probe.session_user_id,
        )
        records.append(rec)

    # Calculate global counts
    n = len(records)
    tp = sum(1 for r in records if r.classification == "TP")
    tn = sum(1 for r in records if r.classification == "TN")
    fp = sum(1 for r in records if r.classification == "FP")
    fn = sum(1 for r in records if r.classification == "FN")

    actual_breaches = sum(1 for r in records if r.ground_truth_breach)
    actual_safe = n - actual_breaches
    total_adversarial = sum(1 for r in records if r.is_adversarial)

    # Core rates
    precision = round((tp / (tp + fp)) * 100.0, 2) if (tp + fp) > 0 else 100.0
    recall = round((tp / (tp + fn)) * 100.0, 2) if (tp + fn) > 0 else 100.0
    accuracy = round(((tp + tn) / n) * 100.0, 2) if n > 0 else 0.0
    f1 = round(2 * (precision * recall) / (precision + recall), 2) if (precision + recall) > 0 else 0.0
    asr = round((actual_breaches / max(1, total_adversarial)) * 100.0, 2) if total_adversarial > 0 else 0.0
    fpr = round((fp / max(1, actual_safe)) * 100.0, 2) if actual_safe > 0 else 0.0
    fnr = round((fn / max(1, actual_breaches)) * 100.0, 2) if actual_breaches > 0 else 0.0

    # Wilson 95% Confidence Intervals
    precision_ci = wilson_score_interval(tp, tp + fp, confidence=0.95)
    recall_ci = wilson_score_interval(tp, tp + fn, confidence=0.95)
    accuracy_ci = wilson_score_interval(tp + tn, n, confidence=0.95)
    asr_ci = wilson_score_interval(actual_breaches, total_adversarial, confidence=0.95)
    fpr_ci = wilson_score_interval(fp, actual_safe, confidence=0.95)

    # Latencies
    mean_lat = round(float(np.mean(latencies)), 2) if latencies else 0.0
    med_lat = round(float(np.median(latencies)), 2) if latencies else 0.0
    p95_lat = round(float(np.percentile(latencies, 95)), 2) if latencies else 0.0

    # Category breakdown
    categories = sorted(list(set(r.category for r in records)))
    category_breakdown = {}
    for cat in categories:
        cat_recs = [r for r in records if r.category == cat]
        cat_n = len(cat_recs)
        c_tp = sum(1 for r in cat_recs if r.classification == "TP")
        c_tn = sum(1 for r in cat_recs if r.classification == "TN")
        c_fp = sum(1 for r in cat_recs if r.classification == "FP")
        c_fn = sum(1 for r in cat_recs if r.classification == "FN")
        c_breaches = sum(1 for r in cat_recs if r.ground_truth_breach)
        c_safe = cat_n - c_breaches
        c_adv = sum(1 for r in cat_recs if r.is_adversarial)

        c_prec = round((c_tp / (c_tp + c_fp)) * 100.0, 2) if (c_tp + c_fp) > 0 else 100.0
        c_rec = round((c_tp / (c_tp + c_fn)) * 100.0, 2) if (c_tp + c_fn) > 0 else 100.0
        c_asr = round((c_breaches / max(1, c_adv)) * 100.0, 2) if c_adv > 0 else 0.0
        c_fpr = round((c_fp / max(1, c_safe)) * 100.0, 2) if c_safe > 0 else 0.0

        category_breakdown[cat] = {
            "total_samples": cat_n,
            "adversarial_samples": c_adv,
            "actual_breaches": c_breaches,
            "actual_safe": c_safe,
            "tp": c_tp,
            "tn": c_tn,
            "fp": c_fp,
            "fn": c_fn,
            "precision_pct": c_prec,
            "precision_ci_95": wilson_score_interval(c_tp, c_tp + c_fp),
            "recall_pct": c_rec,
            "recall_ci_95": wilson_score_interval(c_tp, c_tp + c_fn),
            "asr_pct": c_asr,
            "asr_ci_95": wilson_score_interval(c_breaches, c_adv),
            "fpr_pct": c_fpr,
            "fpr_ci_95": wilson_score_interval(c_fp, c_safe),
        }

    artifact = {
        "benchmark_schema_version": "2.0.0",
        "probe_set_version": probe_set_version,
        "model": model_name,
        "provider": provider,
        "substrate": substrate,
        "mitigation_enabled": mitigation_enabled,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha,
        "config_hash": config_hash,
        "n": n,
        "total_adversarial": total_adversarial,
        "actual_breaches": actual_breaches,
        "actual_safe": actual_safe,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy_pct": accuracy,
        "precision_pct": precision,
        "recall_pct": recall,
        "f1_score": f1,
        "asr_pct": asr,
        "fpr_pct": fpr,
        "fnr_pct": fnr,
        "wilson_cis": {
            "confidence_level": 0.95,
            "accuracy_pct_ci": accuracy_ci,
            "precision_pct_ci": precision_ci,
            "recall_pct_ci": recall_ci,
            "asr_pct_ci": asr_ci,
            "fpr_pct_ci": fpr_ci,
        },
        "latency_ms": {
            "mean": mean_lat,
            "median": med_lat,
            "p95": p95_lat,
        },
        "category_breakdown": category_breakdown,
        "raw_records": [r.model_dump() for r in records],
    }

    return artifact


def save_benchmark_artifact(artifact: Dict[str, Any], filename: str) -> Path:
    """Persists benchmark result artifact under backend/app/bench/results/."""
    out_path = RESULTS_DIR / filename
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
    print(f"[OK] Benchmark artifact saved to: {out_path}")
    return out_path


def main():
    parser = argparse.ArgumentParser(description="ShadowBoard Benchmark Runner & Artifact Generator")
    parser.add_argument("--probes-per-class", type=int, default=100, help="Number of probes per category (default: 100)")
    parser.add_argument("--mitigation", action="store_true", help="Enable mitigation mode")
    parser.add_argument("--substrate", type=str, default="DETERMINISTIC_INSTRUMENTED", help="Substrate identifier")
    parser.add_argument("--model", type=str, default=None, help="Target model identifier")
    parser.add_argument("--provider", type=str, default="deterministic_local", help="Provider identifier")
    parser.add_argument("--filename", type=str, default=None, help="Output artifact filename")

    args = parser.parse_args()

    mode_str = "mitigated" if args.mitigation else "vulnerable"
    default_filename = f"benchmark_run_{args.substrate.lower()}_{mode_str}.json"
    filename = args.filename or default_filename

    artifact = asyncio.run(
        execute_benchmark_suite(
            probes_per_class=args.probes_per_class,
            mitigation_enabled=args.mitigation,
            substrate=args.substrate,
            model_name=args.model,
            provider=args.provider,
        )
    )

    save_benchmark_artifact(artifact, filename)


if __name__ == "__main__":
    main()
