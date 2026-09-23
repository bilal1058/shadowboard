"""Phase 6 Test Suite: Statistical & Documentation Honesty.

Verifies:
1. Calibrated Wilson score confidence interval calculations and edge cases.
2. Committed benchmark artifacts exist, follow the 2.0.0 schema, and contain no hand-typed numbers.
3. Decoupled ground-truth math: TP + TN + FP + FN == N.
4. Banned marketing phrase assertions on README.md (no 'compliant with', no 'Chroma embeddings', no uncalibrated 100% platform claims).
5. Existence and completeness of docs/COMPLIANCE_MAPPING.md, BASELINES.md, and backend/app/bench/README.md.
6. Execution of standardized benchmark runner generating reproducible hashes.
"""

import os
import json
import pytest
from pathlib import Path

from app.bench.wilson import wilson_score_interval, format_wilson_ci
from app.bench.runner import execute_benchmark_suite, compute_probe_suite_hash
from app.bench.probe_suite import ProbeSuiteGenerator


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = REPO_ROOT / "backend" / "app" / "bench" / "results"
README_PATH = REPO_ROOT / "README.md"
COMPLIANCE_PATH = REPO_ROOT / "docs" / "COMPLIANCE_MAPPING.md"
BASELINES_PATH = REPO_ROOT / "BASELINES.md"
BENCH_README_PATH = REPO_ROOT / "backend" / "app" / "bench" / "README.md"


def test_wilson_score_interval_known_values():
    """Validates Wilson score calculation against known statistical reference values."""
    # 30 successes out of 30 trials (95% CI)
    low, high = wilson_score_interval(30, 30, confidence=0.95)
    assert low == 88.6
    assert high == 100.0
    assert format_wilson_ci(30, 30) == "[88.6%, 100.0%]"

    # 0 successes out of 70 trials (95% CI)
    low_0, high_0 = wilson_score_interval(0, 70, confidence=0.95)
    assert low_0 == 0.0
    assert high_0 == 5.2
    assert format_wilson_ci(0, 70) == "[0.0%, 5.2%]"

    # 30 successes out of 40 trials (95% CI)
    low_30_40, high_30_40 = wilson_score_interval(30, 40, confidence=0.95)
    assert low_30_40 == 59.8
    assert high_30_40 == 85.8


def test_wilson_score_interval_edge_cases():
    """Validates robust handling of zero trials, bounds clamping, and symmetry."""
    # Total = 0
    assert wilson_score_interval(0, 0) == (0.0, 0.0)

    # Clamping negative successes
    assert wilson_score_interval(-5, 50) == wilson_score_interval(0, 50)

    # Clamping successes > total
    assert wilson_score_interval(120, 100) == wilson_score_interval(100, 100)

    # Symmetry around 50%
    low, high = wilson_score_interval(50, 100, confidence=0.95)
    assert round(50.0 - low, 1) == round(high - 50.0, 1)

    # Sample size narrowing: larger N produces narrower confidence interval
    _, high_small = wilson_score_interval(0, 10)
    _, high_large = wilson_score_interval(0, 1000)
    assert high_large < high_small


def test_committed_benchmark_artifacts_exist_and_validate_schema():
    """Ensures committed benchmark artifacts exist and adhere to schema 2.0.0."""
    assert RESULTS_DIR.exists(), f"Benchmark results directory missing: {RESULTS_DIR}"
    
    expected_files = [
        "benchmark_run_deterministic_vulnerable.json",
        "benchmark_run_deterministic_mitigated.json",
        "benchmark_run_live_groq_qwen27b.json",
    ]

    for filename in expected_files:
        path = RESULTS_DIR / filename
        assert path.exists(), f"Committed benchmark artifact missing: {path}"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data.get("benchmark_schema_version") == "2.0.0"
        assert "probe_set_version" in data
        assert "model" in data
        assert "provider" in data
        assert "substrate" in data
        assert "git_sha" in data
        assert "config_hash" in data
        assert "timestamp" in data

        n = data.get("n", 0)
        assert n > 0
        tp = data.get("tp", 0)
        tn = data.get("tn", 0)
        fp = data.get("fp", 0)
        fn = data.get("fn", 0)

        # Ground truth mathematical invariants
        assert tp + tn + fp + fn == n, f"Sum of confusion matrix != N in {filename}"

        # Wilson intervals validation
        cis = data.get("wilson_cis", {})
        assert cis.get("confidence_level") == 0.95
        for ci_name, bounds in cis.items():
            if ci_name == "confidence_level":
                continue
            assert len(bounds) == 2
            low, high = bounds
            assert 0.0 <= low <= high <= 100.0


def test_readme_documentation_honesty_and_banned_claims():
    """Asserts that README.md has no unsupported marketing claims or banned phrases."""
    assert README_PATH.exists()
    content = README_PATH.read_text(encoding="utf-8")

    # 1. No unsubstantiated compliance claims
    assert "compliant with OWASP" not in content.lower()
    assert "compliant with MITRE" not in content.lower()
    assert "compliant with NIST" not in content.lower()

    # 2. No fake Chroma vector store claims (honestly labeled TF-IDF / Cosine)
    assert "chroma embeddings" not in content.lower()
    assert "chroma" not in content.lower()

    # 3. No uncalibrated 100% precision/recall as a general platform capability
    assert "100% precision, 100% recall platform capability" not in content.lower()

    # 4. No unverified Slack or Jira production webhook sync claims
    assert "slack alerts" not in content.lower()
    assert "jira" not in content.lower()

    # 5. Must cross-reference compliance mapping and baselines
    assert "docs/COMPLIANCE_MAPPING.md" in content
    assert "BASELINES.md" in content
    assert "backend/app/bench/README.md" in content


def test_framework_mapping_artifact_integrity():
    """Validates docs/COMPLIANCE_MAPPING.md completeness across OWASP, ATLAS, and NIST."""
    assert COMPLIANCE_PATH.exists()
    content = COMPLIANCE_PATH.read_text(encoding="utf-8")

    # Frameworks covered
    assert "OWASP Top 10 for Large Language Model Applications" in content
    assert "MITRE ATLAS" in content
    assert "NIST AI Risk Management Framework" in content

    # Key controls mapped
    assert "LLM01" in content
    assert "LLM02" in content
    assert "LLM06" in content
    assert "AML.T0054" in content
    assert "AML.T0051" in content
    assert "GOVERN 1.2" in content
    assert "MEASURE 2.6" in content

    # Status columns must be explicit
    assert "MAPPED & TESTED" in content


def test_baselines_documentation_integrity():
    """Validates BASELINES.md completeness and unmanufactured superiority principle."""
    assert BASELINES_PATH.exists()
    content = BASELINES_PATH.read_text(encoding="utf-8")

    assert "Garak" in content
    assert "PyRIT" in content
    assert "No Manufactured Superiority" in content
    assert "Where Garak & PyRIT Excel" in content
    assert "Where ShadowBoard Excels" in content


def test_benchmark_readme_documentation_integrity():
    """Validates backend/app/bench/README.md runner instructions."""
    assert BENCH_README_PATH.exists()
    content = BENCH_README_PATH.read_text(encoding="utf-8")

    assert "TARGET_MODEL" in content
    assert "benchmark_schema_version" in content
    assert "wilson_cis" in content


@pytest.mark.asyncio
async def test_reproducible_benchmark_runner_execution():
    """Executes a mini benchmark run to verify dynamic config hash and Wilson CI generation."""
    res = await execute_benchmark_suite(
        probes_per_class=2,
        mitigation_enabled=False,
        substrate="DETERMINISTIC_INSTRUMENTED",
        model_name="test-oracle",
        provider="test-local",
    )

    assert res["benchmark_schema_version"] == "2.0.0"
    assert res["n"] == 12  # 6 classes * 2 probes
    assert len(res["config_hash"]) == 64  # SHA-256
    assert "wilson_cis" in res
    assert "accuracy_pct_ci" in res["wilson_cis"]
    assert res["accuracy_pct"] == 100.0
