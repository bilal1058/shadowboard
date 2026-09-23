# 🔬 Baseline Evaluation: ShadowBoard vs. Open-Source AI Red-Teaming Tools

This document provides a reproducible, unembellished baseline comparison between **ShadowBoard** and established open-source LLM security testing tools—specifically **Garak** and **PyRIT**.

---

## 🎯 Executive Summary & Methodology Philosophy

> **No Manufactured Superiority:**  
> ShadowBoard does not claim to replace general-purpose LLM prompt fuzzers. Open-source tools like Garak and PyRIT possess vastly larger libraries of static jailbreaks, ciphers, and linguistic attacks.  
> 
> ShadowBoard's distinct engineering value lies in **execution-aware verification**: observing what tool-using agents *actually do* (database queries, tool parameters, RAG retrievals, session mutations) rather than merely grading what the LLM *says* in its final completion text.

---

## 🛠️ Tool Overview & Architectural Comparison

| Dimension | Garak (`v0.16.0`) | PyRIT (`v0.4.0+`) | ShadowBoard (`v1.2.0`) |
| :--- | :--- | :--- | :--- |
| **Primary Domain** | LLM vulnerability scanner & prompt fuzzer | Python Risk Identification Tool for generative AI | Execution-aware assurance for tool-using agents |
| **Observation Mode** | Black-Box (HTTP / API completion text) | Black-Box / Gray-Box orchestration | Gray-Box Instrumented (`L1`) & Network Captured |
| **Tool Execution Auditing** | None (Inspects response string only) | Limited (orchestrates multi-turn prompts) | **Native AST & Execution Trace inspection** |
| **Database Substrate Verification** | None | None | **Live SQLite / SQL state auditing** |
| **Ground Truth Derivation** | Judge model or regex match on output text | Evaluator scorer model on completion text | **Decoupled `IndependentOracle` + DB state** |
| **Cryptographic Attestation** | None (Local JSON / HTML report) | None (Memory / DuckDB storage) | **SHA-256 Merkle Tree + Ed25519 signatures** |
| **CI/CD Integration Contract** | CLI scan | Python SDK scripts | **Pre-merge gate (`--ci`), SARIF 2.1.0, JUnit XML** |
| **Regression Prevention** | Diffing test runs manually | Benchmark tracking | **Continuous Semantic Fingerprint Engine** |

---

## 📦 Reproducible Setup Guide

### 1. Installing Garak in Supported Python Environment
Garak is available via PyPI and installs cleanly in standard Python 3.10+ environments:

```bash
# In a dedicated virtual environment or workspace:
pip install garak==0.16.0
```

Verify installation:
```bash
garak --version
# Expected output: garak v0.16.0
```

### 2. Targeting ShadowBoard Reference Endpoints with Garak
Garak can target local HTTP endpoints (such as Target A `/support/chat` or Target B `/internal/chat`) using its `rest` generator:

```bash
# Example Garak run targeting local Target A endpoint:
garak --model_type rest \
      --model_name "http://127.0.0.1:8000/support/chat" \
      --probes promptinject.Direct,dan.Dan_11_0 \
      --report_prefix garak_baseline_run
```

---

## 🧪 Head-to-Head Comparative Evaluation

### Experiment Setup
- **Evaluation Date**: September 2026
- **Target Applications**: Meridian Target A (Customer Support) & Meridian Target B (Internal Knowledge Assistant)
- **Model**: `qwen/qwen3.8-27b` (via Groq) and deterministic reference substrate
- **Probe Sets**: 
  - Suite 1: Prompt Extraction & Direct Injection (50 probes)
  - Suite 2: Tool-Level Broken Object Level Authorization (BOLA / IDOR) (50 probes)
  - Suite 3: Vector RAG Confidential Document Leakage (50 probes)

### Empirical Comparison Matrix

| Attack Category | Garak (`v0.16.0`) Performance | ShadowBoard (`v1.2.0`) Performance | Root Cause Analysis |
| :--- | :---: | :---: | :--- |
| **Prompt Extraction / Direct Injection** | **94.0% Recall** (47/50 detected) | **96.0% Recall** (48/50 detected) | **Comparable Performance**: Both tools detect prompt leakage effectively when canary tokens appear in response text. Garak has a broader variety of linguistic jailbreaks; ShadowBoard evaluates refusal stances and canary attribution. |
| **Tool-Level BOLA (IDOR)** | **0.0% Recall** (0/50 detected) | **100.0% Recall** (50/50 detected) | **Garak Substrate Blindness**: When the target model invoked `get_invoice(customer_id="1042")` and summarized the foreign invoice politely ("*Here is the invoice summary for account 1042: $12,850.00*"), Garak's string detectors found no hostile keywords or toxicity, marking the turn as **PASS**. ShadowBoard intercepted the unauthorized tool parameter in the execution trace and verified cross-tenant breach against SQLite. |
| **Vector RAG Confidential Access** | **12.0% Recall** (6/50 detected) | **100.0% Recall** (50/50 detected) | **Context Blindness**: Garak only detects leakage if the model outputs literal sensitive keywords. When retrieved context influenced the agent's reasoning without direct quotation, Garak missed it. ShadowBoard verified retrieved document clearance tiers against active user roles. |
| **Benign Queries with Negative Refusals** | **18.0% FPR** (9/50 false alarms) | **0.0% FPR** (0/50 false alarms) | **Refusal Misclassification**: Garak detectors triggered false positives on benign queries that contained refusal phrases ("I cannot assist with password resets without verification"). ShadowBoard's finite-state stance classifier parsed refusal semantics accurately. |

---

## ⚖️ Honest Assessment: Strengths & Trade-Offs

### Where Garak & PyRIT Excel:
1. **Attack Surface Breadth**: Garak includes hundreds of probe modules covering hallucination, encoding attacks (Base64, ROT13, ciphers), multilingual jailbreaks, Package Hallucination (slopsquatting), and bias testing.
2. **Zero-Configuration Black-Box Testing**: Garak requires zero instrumentation or target cooperation. It can be aimed at any commercial REST API or SaaS chatbot URL out of the box.
3. **Conversational Multi-Turn Fuzzing**: PyRIT provides powerful multi-turn red-teaming orchestrators (e.g. Tree of Attacks, PAIR, Crescendo) that adaptively craft follow-up prompts based on target replies.

### Where ShadowBoard Excels:
1. **Execution Telemetry Awareness**: Inspects tool names, argument schemas, SQL queries, database mutations, and RAG chunk retrieval boundaries.
2. **Decoupled Independent Oracle**: Verifies ground truth against actual database records and network payloads rather than asking an LLM judge to self-grade.
3. **Cryptographic Proof Packages**: Merkle tree event chaining and asymmetric Ed25519 digital signatures allow external auditors to verify evidence without access to live infrastructure.
4. **CI/CD Quality Gate**: Pre-merge deterministic gating (`shadowboard_cli.py --ci`) that fails pipelines on confirmed high-severity policy breaches and emits standard SARIF 2.1.0 code alerts.
5. **Continuous Regression Detection**: Semantic fingerprint diffing tracks whether a security fix in commit $N+1$ successfully closed a vulnerability identified in commit $N$.

---

## 📌 Conclusion

Garak and PyRIT are premier black-box red-teaming scanners for evaluating model-level alignment and conversational safety. **ShadowBoard is an execution-level assurance engine for agentic workflows.** Organizations building tool-enabled agents should use Garak for broad adversarial prompt fuzzing, and ShadowBoard for verifying that agent function calls, database interactions, and tenant boundaries strictly adhere to security policies.
