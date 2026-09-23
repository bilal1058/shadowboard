# 🛡️ ShadowBoard Framework Compliance & Security Controls Mapping

This document provides a per-control technical crosswalk mapping **ShadowBoard** security policies, evaluators, and test fixtures against industry AI security frameworks:
- **OWASP Top 10 for LLM Applications (2025)**
- **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)**
- **NIST AI Risk Management Framework (AI RMF 1.0)**

---

## 📑 Mapping Methodology & Evidence Standards

Each control entry specifies:
1. **Framework Reference**: Official identifier and title.
2. **ShadowBoard Implementation**: Concrete platform components enforcing the contract (AST policy templates, runtime evaluators, or independent oracles).
3. **Executable Evidence Path**: Verifiable code paths and automated pytest test functions in the repository.
4. **Scope & Limitations**: Explicit boundaries of automated enforcement.
5. **Operational Status**: 
   - `MAPPED & TESTED`: Automated detection rule and unit/integration test exist.
   - `PARTIAL`: Automated heuristics present, but complete coverage requires target-specific instrumentation.
   - `OUT OF SCOPE`: Organizational, governance, or hardware-level controls not evaluated by an automated software harness.

---

## 1. OWASP Top 10 for Large Language Model Applications (2025)

| Control ID | Title | ShadowBoard Implementation | Executable Code & Test Evidence | Scope & Limitations | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **LLM01** | Prompt Injection (Direct & Indirect) | `PolicyRule` `PAC-EXT-INJ-001`<br>`FSMStanceClassifier`<br>Target A Input Defense Firewall | Code: [`backend/app/core/FSM.py`](../backend/app/core/FSM.py)<br>Test: [`backend/tests/test_phase3_detection_quality.py::test_fsm_modern_refusal_boundaries`](../backend/tests/test_phase3_detection_quality.py) | Detects direct override tokens and system prompt injection. Does not guarantee resistance against novel zero-day linguistic ciphers. | `MAPPED & TESTED` |
| **LLM02** | Sensitive Information Disclosure | `PolicyRule` `PAC-CANARY-LEAK-001`<br>`ExecutionAwareEvaluator.audit_trace`<br>Target A Output Scrubber | Code: [`backend/app/verifier/execution_evaluator.py`](../backend/app/verifier/execution_evaluator.py)<br>Test: [`backend/tests/test_phase3_detection_quality.py::test_unprompted_canary_leakage_triggers_complied`](../backend/tests/test_phase3_detection_quality.py) | Enforces forbidden token masking and canary leak detection. Semantic paraphrasing without canaries requires external embedding evaluation. | `MAPPED & TESTED` |
| **LLM06** | Excessive Agency (BOLA / IDOR) | `PolicyRule` `PAC-EXT-BOLA-001`<br>`IndependentOracle.evaluate_bola`<br>Real SQLite DB `enforcement_log` | Code: [`backend/app/bench/oracle.py`](../backend/app/bench/oracle.py)<br>Test: [`backend/tests/test_phase1_integrity.py::test_target_b_bola_cross_tenant_detection`](../backend/tests/test_phase1_integrity.py) | Intercepts tool parameters (e.g. `customer_id`, `account_id`) against session user ID. Requires target to emit tool invocation telemetry. | `MAPPED & TESTED` |
| **LLM07** | System Prompt Leakage | `FSMStanceClassifier._heuristic_evaluate`<br>Prompt Extraction Benchmarks | Code: [`backend/app/core/FSM.py`](../backend/app/core/FSM.py)<br>Test: [`backend/tests/test_shadowboard.py::test_master_verifier_trace_audit`](../backend/tests/test_shadowboard.py) | Verifies disclosure of developer directives and internal system boundaries. | `MAPPED & TESTED` |
| **LLM08** | Vector and Embedding Weaknesses | `PolicyRule` `PAC-EXT-RAG-001`<br>Local TF-IDF Vector Index<br>RBAC Clearance Filter | Code: [`backend/app/internal_rag/rag_store.py`](../backend/app/internal_rag/rag_store.py)<br>Test: [`backend/tests/test_rag_pdf_dataset.py::test_access_tier_classification`](../backend/tests/test_rag_pdf_dataset.py) | Validates document access tiers (`RESTRICTED_CONFIDENTIAL`, `PUBLIC_INTERNAL`) and cross-tenant retrieval. | `MAPPED & TESTED` |
| **LLM10** | Unbounded Consumption / Denial of Service | `ScanQueueManager` Concurrency Cap<br>SSRF 1MB Response Cap | Code: [`backend/app/core/ssrf.py`](../backend/app/core/ssrf.py)<br>Test: [`backend/tests/test_phase0_hygiene.py::test_scan_concurrency_cap_rejects_fourth_scan`](../backend/tests/test_phase0_hygiene.py) | Limits concurrent scan execution (max 3) and bounds network payload sizes. Distributed DoS defense requires edge infrastructure (Cloudflare/AWS WAF). | `MAPPED & TESTED` |

---

## 2. MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

| Technique ID | Technique Name | ShadowBoard Implementation | Executable Code & Test Evidence | Scope & Limitations | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **AML.T0054** | LLM Prompt Injection | FSM Stance Evaluation & Adversarial Probe Suite | Code: [`backend/app/bench/probe_suite.py`](../backend/app/bench/probe_suite.py)<br>Test: [`backend/tests/test_phase3_detection_quality.py::test_prompt_canary_echo_not_flagged_as_complied`](../backend/tests/test_phase3_detection_quality.py) | Evaluates whether target models execute instructions inside user prompts. | `MAPPED & TESTED` |
| **AML.T0051** | LLM Jailbreak | Adversarial Strategy Suite (Roleplay, Debug Mode, Hypotheticals) | Code: [`backend/app/engines/agency.py`](../backend/app/engines/agency.py)<br>Test: [`backend/tests/test_phase2_hardcoded_values.py::test_agency_engine_prompt_parameterization`](../backend/tests/test_phase2_hardcoded_values.py) | Systematic evaluation of 10 adversarial strategies. | `MAPPED & TESTED` |
| **AML.T0057** | LLM Data Leakage | Merkle-Attested Evidence Bundler & Canary Scrubber | Code: [`backend/app/evidence/bundler.py`](../backend/app/evidence/bundler.py)<br>Test: [`backend/tests/test_phase4_cryptography.py::test_evidence_package_creation_and_standalone_verification`](../backend/tests/test_phase4_cryptography.py) | Detects exfiltration of sensitive entities and produces tamper-evident evidence packages. | `MAPPED & TESTED` |
| **AML.T0053** | LLM System Prompt Extraction | Extraction Probe Generators & Oracle Ground Truth | Code: [`backend/app/bench/oracle.py`](../backend/app/bench/oracle.py)<br>Test: [`backend/tests/test_validation_v1.py::test_ground_truth_separation_logic`](../backend/tests/test_validation_v1.py) | Detects unprompted disclosure of internal prompt instructions. | `MAPPED & TESTED` |
| **AML.T0040** | ML Supply Chain / Poisoned External Data | RAG Ingestion Poisoning Test (`trojan_vendor_invoice.md`) | Code: [`backend/app/internal_rag/documents/`](../backend/app/internal_rag/documents/)<br>Test: [`backend/tests/test_rag_pdf_dataset.py::test_vector_search_pdf_trojan_vendor_invoice`](../backend/tests/test_rag_pdf_dataset.py) | Evaluates agent behavior when retrieved knowledge base contains malicious instructions. | `MAPPED & TESTED` |

---

## 3. NIST AI Risk Management Framework (AI RMF 1.0)

| Function / Category | Subcategory | ShadowBoard Implementation | Executable Code & Test Evidence | Scope & Limitations | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **GOVERN 1.2** | Policies and procedures for AI risk management | Declarative Policy-as-Code Compiler (YAML AST) | Code: [`backend/app/policy_engine/compiler.py`](../backend/app/policy_engine/compiler.py)<br>Test: [`backend/tests/test_policy_as_code.py::test_compile_builtin_templates`](../backend/tests/test_policy_as_code.py) | Translates enterprise security policies into executable AST evaluation rules. | `MAPPED & TESTED` |
| **MAP 1.1** | Context and vulnerabilities identified | Multi-Vector Security Probe Suite (600 probes) | Code: [`backend/app/bench/probe_suite.py`](../backend/app/bench/probe_suite.py)<br>Test: [`backend/tests/test_validation_v1.py::test_probe_suite_generation_counts`](../backend/tests/test_validation_v1.py) | Maps potential attack paths across BOLA, RAG, tools, and prompts. | `MAPPED & TESTED` |
| **MEASURE 2.6** | Security and resilience evaluated | Execution-Aware Evaluator & Dynamic Confidence Scoring | Code: [`backend/app/verifier/execution_evaluator.py`](../backend/app/verifier/execution_evaluator.py)<br>Test: [`backend/tests/test_phase3_detection_quality.py::test_policy_evaluator_confidence_is_dynamic`](../backend/tests/test_phase3_detection_quality.py) | Produces calibrated confidence scores and verifiable verdicts without hardcoded constants. | `MAPPED & TESTED` |
| **MEASURE 2.7** | Privacy and confidentiality evaluated | Tenant Boundary Enforcement & RAG Clearance Tiers | Code: [`backend/app/internal_rag/app.py`](../backend/app/internal_rag/app.py)<br>Test: [`backend/tests/test_phase5_honest_targets.py::test_target_b_rbac_clearance_filtering`](../backend/tests/test_phase5_honest_targets.py) | Evaluates cross-tenant data isolation and RBAC document segregation. | `MAPPED & TESTED` |
| **MANAGE 2.4** | Incident tracking & regression detection | Continuous Semantic Fingerprint Regression Engine | Code: [`backend/app/core/replay.py`](../backend/app/core/replay.py)<br>Test: [`backend/tests/test_regression_engine.py::test_regression_detects_new_vulnerability`](../backend/tests/test_regression_engine.py) | Tracks security baselines across git commits and fails CI when regressions occur. | `MAPPED & TESTED` |

---

## 🔒 Out-of-Scope Security Domains

To maintain strict scientific honesty, the following security controls are explicitly **out of scope** for the automated ShadowBoard testbed:
1. **Model Weights Watermarking & Extraction**: ShadowBoard tests inference-time agent execution; it does not evaluate physical model weight exfiltration from GPU memory.
2. **Physical Enclave Attestation (L3)**: Hardware root-of-trust (Intel SGX / AMD SEV) attestation is part of the future architectural roadmap (Phase 8).
3. **Training Data Extraction**: Membership inference attacks against foundational pre-training datasets are not evaluated.
