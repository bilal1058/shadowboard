# 🧪 ShadowBoard Benchmark Suite (`ShadowBoard-Bench`)

This directory contains the standardized, execution-aware evaluation benchmark for testing tool-using AI agents against multi-turn security vulnerabilities.

---

## 📋 Benchmark Philosophy & Statistical Honesty

1. **No Hand-Typed Numbers**: Every metric cited in project documentation and README files is programmatically derived from committed JSON artifacts located in [`backend/app/bench/results/`](results/).
2. **Decoupled Ground Truth**: Ground truth is computed exclusively by the [`IndependentOracle`](oracle.py) from caller network responses, session identity, and real SQLite database state. It **never** reads target self-reported telemetry or evaluator predictions.
3. **Calibrated Wilson Confidence Intervals**: All binomial metrics (Accuracy, Precision, Recall, ASR, FPR) are reported with two-sided 95% Wilson score confidence intervals to explicitly disclose statistical margin of error for finite sample sizes.
4. **Reproducible Config Hashing**: Each run calculates a SHA-256 fingerprint of the active probe suite and records the current Git commit SHA to ensure cryptographic traceability.

---

## ⚙️ Dependencies & Prerequisites

Install required Python dependencies:
```bash
pip install -r backend/requirements.txt
```

### Environment Variables
- `TARGET_MODEL` (Optional): Model name to evaluate (default: `deterministic-oracle-v1` or `qwen-flash`).
- `GROQ_API_KEY` (Optional): Required only when running live LLM benchmarks against Groq-hosted models (e.g. `qwen/qwen3.8-27b`).
- `DASHSCOPE_API_KEY` (Optional): Required if running against Qwen via DashScope.

---

## 🚀 Execution Commands

### 1. Run Controlled Substrate Benchmark (600 Probes)

Runs the systematic 600-probe suite (100 probes per vulnerability class + benign baselines) against deterministic instrumented targets.

**Vulnerable Target:**
```bash
python -m app.bench.runner --probes-per-class 100 --substrate DETERMINISTIC_INSTRUMENTED --filename benchmark_run_deterministic_vulnerable.json
```

**Mitigated / Defended Target:**
```bash
python -m app.bench.runner --probes-per-class 100 --mitigation --substrate DETERMINISTIC_INSTRUMENTED --filename benchmark_run_deterministic_mitigated.json
```

### 2. Run Live LLM Tool-Agent Benchmark (Groq)

Requires `GROQ_API_KEY` in environment or `.env`:
```bash
python -m app.bench.runner --substrate REAL_LLM_INSTRUMENTED --model qwen/qwen3.8-27b --provider groq --filename benchmark_run_live_groq_qwen27b.json
```

### 3. Run Benchmark Suite via Pytest
```bash
pytest backend/tests/test_shadowboard_bench.py -v
```

---

## 📊 Result Artifact Schema

Committed artifacts in [`results/`](results/) adhere to the `2.0.0` benchmark schema:

```json
{
  "benchmark_schema_version": "2.0.0",
  "probe_set_version": "v1.2.0",
  "model": "qwen/qwen3.8-27b",
  "provider": "groq",
  "substrate": "REAL_LLM_INSTRUMENTED",
  "timestamp": "2026-09-15T20:30:57Z",
  "git_sha": "300169f341a8eb7bdb3018f154159bd6cee06b6c",
  "config_hash": "e3b0c442...",
  "n": 100,
  "tp": 30,
  "tn": 70,
  "fp": 0,
  "fn": 0,
  "accuracy_pct": 100.0,
  "precision_pct": 100.0,
  "recall_pct": 100.0,
  "f1_score": 100.0,
  "wilson_cis": {
    "confidence_level": 0.95,
    "accuracy_pct_ci": [96.3, 100.0],
    "precision_pct_ci": [88.6, 100.0],
    "recall_pct_ci": [88.6, 100.0],
    "asr_unmitigated_pct_ci": [59.8, 85.8],
    "fpr_pct_ci": [0.0, 5.2]
  },
  "latency_ms": {
    "median": 3307.0,
    "p95": 6011.2
  }
}
```

---

## 🗂️ Active Benchmark Artifacts

| Artifact Name | Substrate | Probes (N) | Precision (95% CI) | Recall (95% CI) | ASR (95% CI) | FPR (95% CI) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| [`benchmark_run_deterministic_vulnerable.json`](results/benchmark_run_deterministic_vulnerable.json) | Deterministic (Unmitigated) | 600 | 100.0% [99.2%, 100.0%] | 100.0% [99.2%, 100.0%] | 100.0% [99.2%, 100.0%] | 0.0% [0.0%, 3.7%] |
| [`benchmark_run_deterministic_mitigated.json`](results/benchmark_run_deterministic_mitigated.json) | Deterministic (Mitigated) | 600 | 100.0% [0.0%, 100.0%] | 100.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.8%] | 0.0% [0.0%, 0.7%] |
| [`benchmark_run_live_groq_qwen27b.json`](results/benchmark_run_live_groq_qwen27b.json) | Live Groq (`qwen3.8-27b`) | 100 | 100.0% [88.6%, 100.0%] | 100.0% [88.6%, 100.0%] | 75.0% [59.8%, 85.8%] | 0.0% [0.0%, 5.2%] |
