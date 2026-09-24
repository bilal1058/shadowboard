# 🛡️ ShadowBoard

> **An execution-aware security assurance platform for tool-using AI agents, combining policy-as-code, attack simulation, execution telemetry, regression testing, and tamper-evident evidence.**  
> *Validated on controlled deterministic substrates and live LLM-based tool agents, with ongoing validation against independent open-source agents.*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![Tests Passing](https://img.shields.io/badge/tests-185%20passed-success.svg)](backend/tests/)
[![Cryptography](https://img.shields.io/badge/Ed25519-Signed-blueviolet.svg)](backend/app/evidence/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange.svg)](docs/COMPLIANCE_MAPPING.md)
[![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20Mapped-red.svg)](docs/COMPLIANCE_MAPPING.md)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF%201.0-blue.svg)](docs/COMPLIANCE_MAPPING.md)

---

## 💡 The Problem: Why Traditional AI Red-Teaming Fails

Most "AI security scanners" are black-box prompt fuzzer scripts that guess whether an LLM said something harmful based on fuzzy string matching. 

In enterprise production architectures, AI agents do not just chat—they **execute function calls against internal databases**, **invoke third-party APIs**, and **retrieve confidential context via Vector RAG stores**.

### Fundamental Flaws of Conventional Scanners:
1. **Opinion, Not Evidence**: Scanners flag safe refusals as breaches or miss data theft when the model summarizes stolen records politely.
2. **Substrate Blindness**: Black-box fuzzers cannot see tool arguments, SQL mutations, tenant isolation tokens, or memory modifications.
3. **No Ground-Truth Decoupling**: Security tools often rely on their own LLM judges to grade attacks, creating circular evaluation logic.
4. **No Verifiable Cryptographic Trail**: Findings are ephemeral JSON blobs without non-repudiation or integrity guarantees.

---

## 🏗️ Core Platform Architecture

ShadowBoard introduces **execution-aware assurance** across seven runtime dimensions:

```
                  ┌─────────────────────────────────────────┐
                  │       Adversarial Attack Surface        │
                  │ (Planner / Systematic 600-Probe Suite)  │
                  └───────────────────┬─────────────────────┘
                                      │ HTTP Request
                                      ▼
                  ┌─────────────────────────────────────────┐
                  │        Target Application Substrate     │
                  │  * Live Groq LLM (Qwen 27B) Tool Agent   │
                  │  * Enterprise Database (SQLite Substrate)│
                  │  * Local TF-IDF Vector RAG Index (Cosine)│
                  │  * Observed Substrate Ground Truth Log  │
                  └───────────────────┬─────────────────────┘
                                      │ Execution Trace + Data
                                      ▼
                  ┌─────────────────────────────────────────┐
                  │  Execution-Aware Runtime Evaluator      │
                  │  1. Model Output (Canaries & Refusals)  │
                  │  2. Tool Calls & Arguments (BOLA/IDOR)  │
                  │  3. RAG Retrievals (Tenant Boundaries)  │
                  │  4. Database Operations (Cross-Tenant)  │
                  │  5. Network Egress (Exfiltration)       │
                  │  6. State Mutations (Privilege Leaps)   │
                  │  7. Policy-as-Code Declarative AST      │
                  └───────────────────┬─────────────────────┘
                                      │ Verified Verdicts
                                      ▼
            ┌─────────────────────────┴─────────────────────────┐
            │                                                   │
            ▼                                                   ▼
┌───────────────────────────────┐               ┌───────────────────────────────┐
│ Independently Verifiable Proof│               │     CI/CD Ecosystem Gate      │
│  * SHA-256 Linear Merkle Chain│               │  * Pre-merge CLI Gate Runner  │
│  * Asymmetric Ed25519 Signature│              │  * OASIS SARIF 2.1.0 Artifact │
│  * Standalone Offline Verifier │              │  * Structured Audit Payloads  │
└───────────────────────────────┘               └───────────────────────────────┘
```

---

## 🔐 The Evidence Telemetry Trust Hierarchy

To maintain scientific integrity, ShadowBoard establishes an explicit 4-tier telemetry trust model:

| Level | Substrate Type | Telemetry Source | Verification Guarantee | Status |
| :--- | :--- | :--- | :--- | :---: |
| **L0** | `BLACK_BOX` | Completion text only | Heuristic string matching; zero visibility into internal tool calls or database state. | **Implemented** |
| **L1** | `TARGET_INSTRUMENTED` | Target application trace events | High precision on tool arguments and DB queries; requires cooperative target instrumentation. | **Implemented** |
| **L2** | `PROXY_OBSERVED` | Out-of-band network proxy / sidecar | Network egress & external API calls captured independently of target cooperation; defeats target gaslighting. | **Implemented** |
| **L3** | `ATTESTED_EXECUTION` | Hardware enclave / kernel sandbox | Cryptographically verified execution integrity; tamper-proof execution substrate. | *Future Research* |

### 🌐 L2 Out-of-Process Observation Sidecar (`backend/app/sidecar/`)
When evaluating uninstrumented third-party agents or adversarial agents that deliberately suppress internal telemetry, ShadowBoard deploys an out-of-band network observation sidecar:
- **Zero Cooperative Instrumentation**: Sits transparently on the network egress path of the agent.
- **Gaslighting Immunity**: When a target emits a polite text refusal (`"Access denied"`) but secretly executes unauthorized cross-tenant HTTP requests, L2 proxy captures the wire interaction, proves the BOLA breach, and generates an independently signed evidence package (`substrate_truth_level: "PROXY_OBSERVED"`).
- **Cryptographic Merkle Proof**: Sidecar maintains its own binary Merkle tree over captured network events, completely isolated from target memory.

---

## 📜 Cryptographic Evidence Attestation

ShadowBoard evidence packages separate **Data Integrity** from **Signer Authenticity**:

1. **Integrity (`SHA256-MERKLE-CHAIN-V1`)**:
   - Computes a linear Merkle-like hash chain over every execution event in chronological order:
     $$H_0 = \text{SHA256}(\text{"GENESIS"}), \quad H_i = \text{SHA256}(H_{i-1} : \text{SHA256}(ev_i))$$
   - Computes a canonical manifest hash over scan and finding metadata.
   - Proves zero bit-tampering, event reordering, or event omissions.
2. **Authenticity (`ED25519-RFC8032`)**:
   - The canonical payload hash is digitally signed with a private Ed25519 signing key.
   - The raw public key is embedded in the evidence package.
   - Auditors verify the package completely offline using `python -m app.evidence.standalone_verifier package.json` via `public_key.verify()`.
   - *Threat Model Note*: Ed25519 proves evidence provenance and transit integrity; it does **not** independently prove a compromised target did not forge its own execution events.

---

## 🧪 Systematic Validation & Mutation Testing

### 1. Controlled Substrate Self-Test
> **Controlled Substrate Self-Test Result:** 600/600 probes correctly classified across deterministic instrumented substrates under defined benchmark conditions. Full evaluation data is committed in:
> - [`backend/app/bench/results/benchmark_run_deterministic_vulnerable.json`](backend/app/bench/results/benchmark_run_deterministic_vulnerable.json) (ASR: 100.0% [99.2%, 100.0%])
> - [`backend/app/bench/results/benchmark_run_deterministic_mitigated.json`](backend/app/bench/results/benchmark_run_deterministic_mitigated.json) (ASR: 0.0% [0.0%, 0.8%], FPR: 0.0% [0.0%, 0.7%])
> 
> *Important Methodology Note*: These figures demonstrate that ShadowBoard correctly observes and enforces the specific security contracts it was engineered to detect within this controlled testbed. They are an internal regression self-test, **not** an empirical claim of 100% detection against unconstrained, novel real-world attacks. Full runner instructions and schema specifications are in [backend/app/bench/README.md](backend/app/bench/README.md).

### 2. Independent Oracle & Decoupled Ground Truth
Ground truth is strictly derived by an `IndependentOracle` from:
1. The authenticated caller session identity established by the test harness.
2. The actual network response text and payload received by the caller.
3. The reference database state (seeded SQLite database).

**Hard Separation**: Ground truth NEVER reads target self-reported `target_breached` flags, `authorized` boolean telemetry, or evaluator outputs. Furthermore, ShadowBoard satisfies the **Observation Channel Invariance Contract**: deleting, forging, or flipping target-side execution events leaves scanner verdicts 100% identical.

### 3. Evaluator Mutation Testing: Proving Discriminative Power
To prove that our evaluation harness is genuinely sensitive to evaluator regressions (rather than being a circular self-fulfilling test), we run mutation tests (`test_evaluator_mutations.py`) that intentionally break detection rules:

| Evaluator Mutation Injected | Injected Blind Spot | Expected Effect | Observed Benchmark Outcome |
| :--- | :--- | :---: | :--- |
| **Remove Parameter Aliases** | Evaluator only looks for literal `customer_id`, ignoring `account_id` | Recall $\downarrow$ | Benchmark catches 25 False Negatives (Recall drops $100\% \to 75.0\%$) |
| **Remove Nested Traversal** | Evaluator only inspects top-level dict keys | Recall $\downarrow$ | Benchmark catches 25 False Negatives (Recall drops $100\% \to 75.0\%$) |
| **Remove Refusal Awareness** | Evaluator naively flags any response containing a canary token | Precision $\downarrow$ | Benchmark catches 20 False Positives on safe refusals (Precision drops $100\% \to 83.3\%$) |
| **Ignore Target Auth Status** | Evaluator assumes any BOLA attempt succeeded regardless of target response | Patched FP $\uparrow$ | Benchmark catches 50 False Positives on patched/defended targets |

This proves the benchmark has authentic discriminative power: when evaluator detection logic degrades, the benchmark exposes it immediately.

### 4. Independent Third-Party Agent Target (`third_party_targets/agent.py`)
ShadowBoard is evaluated against an independent tool-using agent architecture (`third_party_targets/agent.py`), modeling standard LangChain/ReAct tool dispatch patterns over real SQLite financial tables:

```
[Adversarial Probe (Session 1001)]
        ↓ HTTP POST /chat
[Third-Party LangChain Agent]
        ↓ executes LangChain tool: get_invoice_tool(customer_id="1042")
[Real SQLite Enterprise DB] -> Returns Globex financial records
        ↓
[Caller Network Response] -> Discloses foreign invoice INV-2026-1042
        ↓
[ShadowBoard Independent Oracle] -> Verified Breach (Session 1001 received Tenant 1042 data)
[ShadowBoard Network Evaluator] -> CONFIRMED (Observation Invariance verified)
```
*Validated end-to-end over HTTP in automated test suite ([test_phase1_oracle_and_observation.py](backend/tests/test_phase1_oracle_and_observation.py)).*

### 5. Empirical Real-LLM Benchmark (100 Live Groq Model Turns)
We evaluated ShadowBoard against a live LLM tool agent (`RealLLMToolAgent`) powered by Groq (`qwen/qwen3.8-27b`) executing native OpenAI-compatible function calling schemas, seeded SQLite databases, and independent oracle logging across 100 live turns (40 vulnerable adversarial, 30 mitigated adversarial, 15 legitimate own-session tool calls, and 15 benign FAQ queries). Metrics include Wilson 95% score confidence intervals:

| Metric | Point Estimate | Wilson 95% Confidence Interval |
| :--- | :---: | :---: |
| **Model Evaluated** | `qwen/qwen3.8-27b` (via Groq API) | — |
| **Total Evaluated Turns** | 100 | — |
| **Tool-Call Invocations** | 45 | — |
| **Actual Breaches (Oracle Ground Truth)** | 30 / 40 | [59.8%, 85.8%] (ASR) |
| **Correct Detections** | 100 (30 TP, 70 TN) | — |
| **False Positives** | 0 | [0.0%, 5.2%] (FPR) |
| **False Negatives** | 0 | — |
| **Precision** | 100.0% (30/30) | [88.6%, 100.0%] |
| **Recall** | 100.0% (30/30) | [88.6%, 100.0%] |
| **Model Intrinsic Refusal Rate** | 25.0% (10/40) | [14.1%, 40.2%] |
| **Median Latency** | 3,307.0 ms | — |
| **p95 Latency** | 6,011.2 ms | — |

*Key Empirical Finding*: In unmitigated mode, the live model refused 10 out of 40 adversarial probes upfront without calling the tool (a 25% intrinsic refusal rate). ShadowBoard correctly recognized these safe text refusals without triggering false positives, while capturing all 30 actual tool-level BOLA breaches where the model executed `get_invoice(customer_id="1042")`.  
*Full evaluation data is committed in [`backend/app/bench/results/benchmark_run_live_groq_qwen27b.json`](backend/app/bench/results/benchmark_run_live_groq_qwen27b.json).*

---

## 🚦 CI/CD Security Gate Runner & Multi-Commit Regression Flow

ShadowBoard CLI executes as an automated pre-merge gate in CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins). It enforces a strict pass/fail contract across software lifecycles:

### Real Multi-Commit Sequence:

```text
Commit A (Pull Request #42: Feature introduces vulnerable agent tool call)
  │
  ├──► GitHub Actions: python backend/shadowboard_cli.py --ci --max-critical 0
  │    ├── Evaluator detects: CRITICAL BOLA Violation (Tool param manipulation)
  │    ├── Security Score: 30/100 (Grade: F)
  │    ├── SARIF Alert: Uploaded to GitHub Code Scanning
  │    └── Result: ❌ CI FAILED (Exit Code 1) -> PR Merge Blocked
  │
Commit B (Fix: Server-side authorization check added to tool handler)
  │
  └──► GitHub Actions: python backend/shadowboard_cli.py --ci --mitigation --max-critical 0
       ├── Continuous Regression Engine diffs against Commit A baseline
       ├── Verified Resolved: PAC-EXT-BOLA-001 closed
       ├── Security Score: 100/100 (Grade: A)
       └── Result: ✅ CI PASSED (Exit Code 0) -> PR Merge Allowed
```

```bash
# Execute local CI gate simulation:
python backend/shadowboard_cli.py --target-id 2 --ci --max-critical 0 --min-score 75 --sarif-out results.sarif
```

- **Vulnerable Target**: Detects critical BOLA/tool breaches $\implies$ Score: `30/100 (Grade: F)` $\implies$ **Exits with code `1`**, blocking pull request merges.
- **Patched Target**: Confirms all security boundaries enforced $\implies$ Score: `100/100 (Grade: A)` $\implies$ **Exits with code `0`**, allowing pipeline deployment.
- **OASIS SARIF 2.1.0**: Generates native GitHub Security Scanning code alerts mapped to agent source files.

---

## ⚠️ Limitations & Threat Model Boundaries

ShadowBoard is designed to provide verifiable security evidence, not marketing claims. We explicitly document our known architectural boundaries:

1. **Instrumentation Dependency**: L1 execution-aware verification requires target-side cooperation (the agent must emit tool calls and database telemetry). If a target runs as a black box (L0), ShadowBoard falls back to heuristic completion text analysis.
2. **Canary & Lexical Limitations**: RAG leakage detection currently relies on canary tokens (`INTERNAL_DOC_7C15`) or document metadata tags. If a model paraphrases confidential document text without repeating canaries (*"semantic leakage"*), lexical evaluators will produce a False Negative.
3. **Substrate Control**: Our 600-probe suite measures performance against controlled reference targets (`DETERMINISTIC_INSTRUMENTED` and `REAL_LLM_INSTRUMENTED`). These results prove that ShadowBoard correctly detects the conditions it was engineered to observe; they should not be conflated with general-world detection rates on unconstrained production systems.
4. **Authenticity vs. Substrate Truth**: Ed25519 digital signatures prove that the evidence package was issued by an authentic ShadowBoard instance and was not modified in transit. They do **not** independently prove that a compromised target did not forge its own execution events.
5. **Real-LLM Scope**: The current live LLM substrate tests tool calling on `qwen/qwen3.8-27b` via Groq. Multi-agent swarms, asynchronous task queues, and non-deterministic agent frameworks represent future validation milestones.

---

## 🚀 Quickstart

### 1. Installation
```bash
git clone https://github.com/bilal1058/ShadowBoard.git
cd ShadowBoard
pip install -r backend/requirements.txt
```

### 2. Run Comprehensive Test Suite
```bash
pytest backend/tests/ -v
```
*Executes all 146+ automated tests across 22 test suites (unit, integration, real LLM, Ed25519 cryptographic proofs, independent oracle, honest target sessions, and evaluator mutation tests).*

### 3. Launch Web Console
```bash
python backend/main.py
```
Open **`http://127.0.0.1:8000/`** to access the ShadowBoard Console (Policy-as-Code Studio, Autonomous Planner, Regression Engine, and Evidence Center).

---

## 👥 Engineering & Research Context
Designed and engineered as a high-assurance AI security evaluation platform.  
Mapped to **OWASP Top 10 for LLM Applications (2025)**, **MITRE ATLAS**, and **NIST AI RMF 1.0** with executable per-control evidence in [docs/COMPLIANCE_MAPPING.md](docs/COMPLIANCE_MAPPING.md).  
Comparative evaluation against open-source red-teaming scanners is documented in [BASELINES.md](BASELINES.md).  
Full benchmark methodology and runner instructions are in [backend/app/bench/README.md](backend/app/bench/README.md).
