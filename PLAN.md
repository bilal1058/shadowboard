# ShadowBoard Remediation Plan & Execution Audit Ledger

## 0.0 Security Emergency Declaration

> [!CAUTION]
> **CRITICAL SECURITY ALERT — COMPROMISED API KEYS**
> 
> The local environment (`backend/.env`) contained live credentials for **Groq API** (`GROQ_API_KEY`, prefix `gsk_`) and **OpenRouter API** (`OPENROUTER_API_KEY`, prefix `sk-or-`).
>
> **Action Required by Repository Owner:**
> 1. **IMMEDIATELY REVOKE AND ROTATE** both the Groq API key and the OpenRouter API key in their respective provider web dashboards.
> 2. Assume these credentials are compromised.
> 3. Keys have been removed from the working tree.
> 4. Per security policy, the actual secret strings are **never copied into this document, logs, or git commits**.

### Git History Secret & Artifact Audit Findings
- **Git Commit History Analysis**:
  - `git log --all --full-history -- backend/.env`: Empty (file was untracked/local, never committed to git tree).
  - `git log --all --full-history -- backend/shadowboard.db`: Empty (runtime artifact was local, never committed to git tree).
  - `git rev-list --objects --all`: Swept all commit trees. Only placeholder `.env.example` and synthetic test canaries were found in commit history.
  - Working tree actions:
    - Purged `backend/.env` from working tree.
    - Purged `backend/shadowboard.db` (1.3MB runtime database) from working tree.
    - Added `.env`, `*.db`, `*.db-journal`, `*.db-wal`, `*.sqlite`, `*.sqlite3`, `__pycache__/`, `.venv/` to `.gitignore`.
  - Secret Pattern Sweep across repo:
    - Found synthetic test canary strings: `whsec_9942a8b17c330f81d9e` in RAG test dataset (`infrastructure_master_secrets.md`), `INTERNAL_AUTH_4B72`, `INTERNAL_DOC_7C15`, `INTERNAL_ESC_9F31`. These are test artifacts, not active infrastructure secrets.
    - `_DEFAULT_PRIVATE_KEY` in `backend/app/evidence/bundler.py` generates an in-memory ephemeral keypair; will be replaced with explicit configuration in Phase 4.

---

## 1. Operating Rules Alignment & Working State

- **Baseline Environment**:
  - Python: `3.10.11` (compatible with 3.11+)
  - Test Suite Baseline: **82 passed, 4 warnings in 23.34s** across 20 test files.
- **Preserved Core Capabilities**:
  - CI gate CLI (`shadowboard_cli.py --ci`)
  - SARIF report export (`github_sarif.py`)
  - SSE real-time scan event streaming (`/api/scans/{id}/stream`)
  - SQLite persistence (`app/db/session.py`)
  - Policy-as-Code schema and compiler (`app/policy_engine/compiler.py`)
  - Mutation testing architecture (`test_evaluator_mutations.py`)
  - Cryptographic evidence package verification (`app/evidence/standalone_verifier.py`)

---

## 2. README Marketing vs. Actual Code Discrepancies

| Topic | README Marketing Claim | Code Reality (Ground Truth) | Remediation Phase |
| :--- | :--- | :--- | :--- |
| **Accuracy** | "100% precision, 100% recall" platform capability | 600-probe self-authored benchmark where probes mirror evaluator parameter names; 48 unique templates. | Phase 1 & 6 |
| **Observation Mode** | "Out-of-band zero-knowledge observation" | Consumes target self-reported execution trace events; no out-of-band proxy. | Phase 1 & 8 |
| **Cryptography** | "Ed25519 Merkle Tree" | Sequential SHA-256 hash chain with Ed25519 digital signature of manifest. | Phase 4 & 6 |
| **Infrastructure** | "Postgres, Redis, Sentry, Prometheus, Grafana" | SQLite-only application; Redis is unused; Alembic migrations directory is empty. | Phase 0 & 2 |
| **Frontend** | "Enterprise React Security Console" | Monolithic 246KB hand-written static HTML (`backend/static/index.html`); `frontend/src/App.tsx` had recursive self-import. | Phase 0 |
| **Confidence** | "0.98 calibrated confidence score" | Hardcoded float literals (`0.98`, `0.92`, `0.85`) based on telemetry availability. | Phase 3 |
| **Integrations** | "Production Slack & Jira sync" | Mock logging functions assembling dict payloads without webhooks. | Phase 6 |

---

## 3. Phase Status & Progress Tracker

| Phase | Description | Status | Test Command | Result | Commit SHA |
| :---: | :--- | :---: | :--- | :--- | :--- |
| **0** | Security Emergency & Reproducibility Hygiene | **GREEN / COMPLETED** | `pytest backend/tests -v` & `npm run build` | 89 passed, 1 skipped, 0 failed; Vite build clean in 1.75s | `3f8daac` |
| **1** | Break Circular Ground Truth & Independent Oracle | **GREEN / COMPLETED** | `pytest backend/tests -v` | 96 passed, 1 skipped, 0 failed in 6.50s (7/7 Phase 1 tests passed) | `f9959eb` |
| **2** | Remove Hardcoded Demo Values from Paths | **GREEN / COMPLETED** | `pytest backend/tests -v` | 103 passed, 1 skipped, 0 failed in 6.99s (7/7 Phase 2 tests passed) | `51da388` |
| **3** | Detection Quality & Refusal / Stance Boundaries | **GREEN / COMPLETED** | `pytest backend/tests -v` | 119 passed, 1 skipped, 0 failed in 9.61s (16/16 Phase 3 tests passed) | `d547e68` |
| **4** | Real Evidence Cryptography & Key Registry | **GREEN / COMPLETED** | `pytest backend/tests` | 136 passed, 1 skipped, 0 failed in 6.93s (17/17 Phase 4 tests passed) | `4a098c0` |
| **5** | Honest Targets & Session-Isolated Mitigation | **GREEN / COMPLETED** | `pytest backend/tests -v` | 146 passed, 1 skipped, 0 failed in 7.66s (10/10 Phase 5 tests passed) | `4426e4b` |
| **6** | Statistical & Documentation Honesty | **GREEN / COMPLETED** | `pytest backend/tests -v` | 154 passed, 1 skipped, 0 failed in 11.20s (8/8 Phase 6 tests passed) | `ab5b308` |
| **7** | Permanent CI Regression Enforcement Suite | **GREEN / COMPLETED** | `pytest backend/tests -v` & `python scripts/ci_enforcement_audit.py` | 177 passed, 1 skipped, 0 failed in 8.67s; 23/23 CI invariant tests passed; Standalone audit passed (7/7 checks) | `926a538` |
| **8** | (Optional) Out-of-Process Observation Sidecar | **GREEN / COMPLETED** | `pytest backend/tests/test_phase8_observation_sidecar.py -v` | 185 passed, 1 skipped, 0 failed in 9.86s (8/8 Phase 8 tests passed); Standalone L2 sidecar verified | `d481471` |

---

## 4. Phase 0 Detailed Execution Log

- [x] **0.0 Emergency**: Declared compromised keys in PLAN.md. Swept git history and working tree (0 secret patterns found).
- [x] **0.0 Clean Filesystem**: Purged local `backend/.env` and `backend/shadowboard.db` runtime artifact. Verified `.gitignore` covers `.env`, `*.db`, `__pycache__/`, `.venv/`.
- [x] **0.1 Dependencies**: Audited `backend/requirements.txt`, pinned exact versions (`fastapi==0.139.0`, `pydantic==2.13.4`, `cryptography==50.0.1`, etc.), added missing `groq==0.37.1`, purged unused packages (`redis`, `python-jose`, `passlib`, `alembic`, `asyncpg`). Pytest baseline: 82 passed.
- [x] **0.2 Frontend Reconciliation**: Fixed recursive self-import in `frontend/src/App.tsx`. Deleted dead entry `frontend/src/index.ts`. Replaced `frontend/index.html` with clean template referencing `/src/main.tsx`. Implemented real, fully typed `frontend/src/pages/Dashboard.tsx` with target switching, scan trigger, SSE streaming, and auth modal. Fixed postcss config and tailwind directives. Verified `npm run build` builds cleanly in 1.75s. Replaced monolithic 246KB hand-written `backend/static/index.html` with Vite build output.
- [x] **0.3 Docker & Scaffolding Cleanup**: Added `/api/health` and `/health` endpoints. Fixed dev `Dockerfile` `CMD ["python", "backend/main.py"]` and fixed `requirements.txt` COPY path. Created multi-stage `Dockerfile.prod` hitting `/api/health`. Deleted ornamental `backend/alembic/`, `backend/app/alembic/`, `nginx/`, and `monitoring/`. Stripped unused postgres/redis declarations from `docker-compose.yml` and `docker-compose.prod.yml`. Documented local Docker daemon offline environmental blocker per Rule 6 (verified in CI).
- [x] **0.4 Config**: Updated `.env.example` with `SHADOWBOARD_ADMIN_KEY=`, `SHADOWBOARD_API_KEY=`, `DASHSCOPE_API_KEY=`, `TARGET_MODEL=qwen-flash`, `CORS_ORIGINS=http://127.0.0.1:8000`, `SIGNING_KEY_PATH=`, `KEY_ID=`. Documented required vs optional.
- [x] **0.5 Central Auth**: Implemented `AdminAuthMiddleware` in `backend/app/core/middleware.py` enforcing `SHADOWBOARD_ADMIN_KEY` on all `/api` routes (except `/api/health`, `/health`, `/docs`, `/openapi.json`, and target sub-apps) with constant-time comparison (`secrets.compare_digest`). Fail-closed in non-test environments if unset.
- [x] **0.6 CORS**: Strict configuration-driven CORS; default `http://127.0.0.1:8000`. Validator strictly prohibits wildcard `*` with credentials.
- [x] **0.7 SSRF**: Implemented `backend/app/core/ssrf.py` with DNS resolution, RFC1918 private / loopback / link-local / cloud metadata (`169.254.169.254`) blocking, safe redirect following with validation on every step, and 1MB size cap. Wired into `/api/targets` and `/api/targets/test-connection`.
- [x] **0.8 SSE Lifecycle**: Enforced bounded subscriber queues (size 100), graceful `cleanup_sse_scan` purging `sse_queues` scan entries, and terminal event broadcasting.
- [x] **0.9 Concurrency**: Enforced max 3 concurrent scans via `active_scans` set and lock; 4th scan rejected with HTTP 429 Too Many Requests (`Retry-After: 5`). Scans execute with isolated state.
- [x] **Phase 0 Tests**: Created `backend/tests/test_phase0_hygiene.py` covering auth, fail-closed mode, CORS wildcard ban, SSRF schemes/IPs, SSRF API endpoints, SSE lifecycle, and concurrency cap. Total test suite: 89 passed, 1 skipped, 0 failed.

---

## 5. Phase 1 Detailed Execution Log

- [x] **1.1 Real Database Substrate**: Created `backend/app/bench/invoice_db.py` with Postgres-compatible DDL (`customers`, `invoices`, `enforcement_log`). Deterministically seeds customer 1001, 1042, and batch accounts 1043–1074. Stores zero expected verdicts.
- [x] **1.2 Target Decoupling**: Refactored `backend/app/bench/target_substrates.py`:
  - Completely purged in-memory `ENTERPRISE_INVOICES` dictionary and `ObservableAuditLedger` synthetic flags (`unauthorized_cross_tenant`).
  - Vulnerable targets execute raw SQL `fetch_invoice_records(conn, cid)` against the real SQLite database.
  - Mitigated targets enforce server-side isolation, write to `enforcement_log` table, and return 403-style refusal.
  - All emitted target telemetry is explicitly tagged `source: "target_untrusted"`.
  - Target substrates no longer calculate `target_breached` verdicts.
- [x] **1.3 Independent Oracle**: Created `backend/app/bench/oracle.py` with `IndependentOracle`:
  - Derives ground truth strictly from: (1) authenticated session identity $S$, (2) caller-received network response text / body, and (3) reference database state.
  - Hard constraint: NEVER reads target `target_breached` flags, evaluator outputs, confidence scores, or target telemetry.
  - Evaluates all benchmark categories: BOLA, Tool Governance, RAG Canary Leakage, Prompt Extraction, Memory Poisoning, and Benign edge cases.
- [x] **1.4 Decoupled Ground Truth**: Updated `EvaluationEngine.evaluate_probe` in `backend/app/bench/evaluation_engine.py` to use `IndependentOracle().evaluate_probe_outcome()`. Proved via unit test that mutating target self-reported `target_breached` flags has zero effect on ground truth.
- [x] **1.5 Observation Channel Invariance**: Added `audit_network_observation` to `ExecutionAwareEvaluator` in `backend/app/verifier/execution_evaluator.py`:
  - Verifier determines `CONFIRMED` and `PASS` from network-observable request/response (a) alone.
  - Acceptance tests prove that deleting (`[]`), forging (denial or success), or flipping target-side execution events leaves all verdicts 100% identical.
- [x] **1.6 Third-Party LangChain Target**: Implemented `backend/third_party_targets/agent.py` exposing independent HTTP endpoints (`/chat`, `/health`, `/config/mitigation`), executing LangChain tools (`get_invoice_tool`) against real SQLite tables. Verified via HTTP client tests.
- [x] **1.7 Evaluator Mutation Testing Alignment**: Refactored `backend/tests/test_evaluator_mutations.py` to run against decoupled SQLite substrate and independent oracle, proving that evaluator mutations trigger exact False Negative and False Positive regressions.
- [x] **1.8 Phase 1 Test Suite**: Implemented `backend/tests/test_phase1_oracle_and_observation.py` covering database schemas, oracle independence, ground truth decoupling, observation channel invariance, and third-party LangChain target. All 7 tests pass.
- [x] **1.9 Documentation Honesty**: Renamed 600-probe benchmark in `README.md` to "Controlled Substrate Self-Test", documented Wilson 95% score confidence intervals for real LLM validation, updated test badge to 96 passed.

---

## 6. Phase 2 Detailed Execution Log

- [x] **2.1 Target B Dynamic Customer ID & Invoice Substrate**:
  - Replaced static `ENTERPRISE_INVOICE_DB` dictionary in `backend/app/internal_rag/app.py` with `get_shared_invoice_db()`, `fetch_invoice_records()`, and `log_enforcement_action()`.
  - Replaced hardcoded `target_cid = "1042" if ("1042" in lower_query ...)` with multi-stage regex extraction distinguishing customer/account/tenant IDs from invoice year prefixes (`INV-2026-X`).
  - Replaced static `$12,850.00` fallback with dynamic amount calculation.
- [x] **2.2 Dynamic Sandbox Probe Validation**:
  - Refactored `execute_sandbox_probe()` in `backend/app/api/endpoints/scans.py`.
  - Replaced hardcoded `has_unauthorized_invoice = any("Invoice returned" in str(e) and "1042" in str(e))` with structured event parsing comparing returned invoice `customer_id` against `request.session_user_id`, plus response text cross-tenant regex extraction.
  - Replaced hardcoded pitch-deck slide check (`"10,000" in response_text and "compensation" in response_text.lower()`) with general false premise compliance detection.
- [x] **2.3 Master Verifier Regex Generalization**:
  - Refactored `_verify_heuristic()` in `backend/app/verifier/engine.py`.
  - Replaced literal `"INV-1042"` and `"$12,850.00"` checks with generalized invoice regex (`\bINV-(?:2026-)?\d+\b`) and currency pattern detection.
  - Dynamically populates `detected_pattern` with the actual matched pattern rather than hardcoded `"INV-1042 / $12,850.00"`.
- [x] **2.4 Execution Evaluator Dynamic Foreign Entity Attribution**:
  - Refactored `audit_network_observation()` in `backend/app/verifier/execution_evaluator.py`.
  - Replaced hardcoded `str(session_user_id) == "1001"` and `"globex enterprise"` with general foreign enterprise pattern extraction (`Enterprise Account #<id>`) and tenant boundary enforcement that prevents false positives when the owner tenant accesses their own company.
- [x] **2.5 AgencyEngine Strategy Prompt Parameterization**:
  - Refactored `STRATEGY_PROMPTS` in `backend/app/engines/agency.py` across all 60 prompt templates and 10 strategies.
  - Replaced literal `"1042"`, `"1001"`, and `"INV-2026-1042"` with `{target_tenant}`, `{session_user_id}`, and `{invoice_id}` placeholders.
  - Updated `AgencyEngine.build_prompt()` to accept dynamic `target_tenant` and `session_user_id` kwargs with backwards-compatible defaults.
- [x] **2.6 Schema Analyzer Generalization**:
  - Updated `backend/app/planner/schema_analyzer.py` line 93 to replace literal `(1042)` with generic placeholder `(<target_tenant>)`.
- [x] **2.7 Targets & Substrates Dynamic Calculations**:
  - Updated `backend/app/bench/targets.py` (`ToolGatedAgent`), `backend/app/bench/target_substrates.py` (`DeterministicTargetExecutor`, `LiveGroqToolAgentExecutor`), and `backend/third_party_targets/agent.py` to extract customer IDs via regex and dynamically calculate unseeded fallback amounts.
- [x] **2.8 Phase 2 Test Suite**:
  - Created `backend/tests/test_phase2_hardcoded_values.py` covering dynamic customer ID queries, AgencyEngine prompt interpolation, black-box regex matching, execution evaluator foreign entity attribution, AgentBeta dynamic queries, unseeded tenant amounts, and sandbox probe multi-tenant breach detection.
  - All 7 tests pass. Full test suite: **103 passed, 1 skipped, 0 failed in 6.99s**.

---

## 7. Phase 3 Detailed Execution Log

- [x] **3.1 Calibrated Dynamic Confidence Scoring**:
  - Eliminated all hardcoded float constants (`0.98`, `0.92`, `0.85`, `0.60`, etc.) across `backend/app/verifier/execution_evaluator.py`, `backend/app/core/FSM.py`, and `backend/app/policy_engine/evaluator.py`.
  - Implemented dynamic confidence calculation based on active evidence signals, observation sample size, violation severity weights, refusal marker density, and trace audit depth.
- [x] **3.2 Input/Output Attribution in FSM**:
  - Implemented prompt canary attribution in `FSMStanceClassifier._heuristic_evaluate`: canary tokens echoed from the adversarial prompt (`prompt.lower()`) do NOT trigger `COMPLIED`.
  - Genuine unprompted canary leaks continue to trigger `COMPLIED` with calibrated signal-based confidence.
- [x] **3.3 Runtime Action Precedence over Polite Apologies**:
  - Enforced runtime event precedence in `FSMStanceClassifier`: unauthorized tool calls, database mutations, or state escalations in `execution_events` classify as `COMPLIED` immediately, regardless of text apologies or refusal phrasing.
  - In `ExecutionAwareEvaluator.audit_network_observation`: unmasked sensitive tool execution (`executed sensitive tool`), session privilege escalation (`role set to security_officer_superuser`), and financial data disclosure (`$12,850.00` alongside cross-tenant invoice ID) so explicit refusal apologies cannot suppress confirmed breaches.
- [x] **3.4 Modern Refusal & Evasive Stance Boundaries**:
  - Expanded refusal dictionary in `FSM.py` with modern variations (`"unable to fulfill"`, `"against operational guidelines"`, `"as an ai assistant"`, `"restricted under"`, `"prohibited by enterprise policy"`, etc.).
  - Preserved warning/discussion boundary (`"appears to be a prompt injection"` -> `REFUSED`) and generic deflection boundary (`"how else can i assist"` -> `EVASIVE`).
- [x] **3.5 Policy Evaluator Calibrated Scoring**:
  - Replaced static confidence across all policy conditions (`tool_parameter`, `rag_tenant_isolation`, `human_in_the_loop`, `forbidden_tokens`, `document_confidentiality`) with dynamic scores derived from argument presence, chunk validity, token specificity, and trace depth.
- [x] **3.6 Phase 3 Test Suite**:
  - Created `backend/tests/test_phase3_detection_quality.py` with 16 tests covering prompt canary echo attribution, unprompted canary leakage, runtime action precedence over polite apologies, network observer refusal unmasking, dynamic confidence variability across all evaluators, and modern refusal/evasive boundaries.
  - All 16 tests pass. Full test suite: **119 passed, 1 skipped, 0 failed in 9.61s**.

---

## 8. Phase 4 Detailed Execution Log

- [x] **4.1 Binary Merkle Tree Implementation**:
  - Implemented `MerkleTree` in `backend/app/evidence/merkle.py` with deterministic JSON serialization (`canonical_json_bytes`).
  - Domain separation: leaf hashing uses prefix byte `0x00`, internal node hashing uses prefix byte `0x01` (prevents second preimage attacks).
  - Implemented audit path generation (`get_inclusion_proof(index)`) and independent audit path verification (`verify_inclusion(item, proof, root)`).
  - Proved event order sensitivity and tamper resistance via unit tests.
- [x] **4.2 Key Registry & PKI System**:
  - Created `backend/app/evidence/key_registry.py` with `KeyRecord` metadata model and `KeyRegistry` manager.
  - Supports persistent private key loading and generation from `SIGNING_KEY_PATH` (PEM PKCS#8 format) with fallback to instance directory `backend/.keys/shadowboard_signing_key.pem`.
  - Supports key rotation (`rotate_key`) maintaining previous keys for historical verification.
  - Supports key revocation (`revoke_key`) with timestamps and structured revocation reasons.
  - Provides JSON export (`export_keyring`) and import (`import_keyring`) for offline third-party audit verification.
  - Provided singleton `get_active_key_registry()` and test isolation helper `reset_key_registry()`.
- [x] **4.3 Evidence Bundler Cryptographic Proof**:
  - Updated `backend/app/evidence/bundler.py`:
    - Updated `CryptographicProof` model to embed `key_id`, `event_merkle_root`, and public key hex.
    - Updated `EvidenceBundler.create_package` to fetch active key and key ID from `get_active_key_registry()`, compute both the linear Merkle chain hash and binary Merkle tree root over execution events, sign the canonical payload with real Ed25519, and register public key.
- [x] **4.4 Standalone Verifier Offline Verification**:
  - Updated `backend/app/evidence/standalone_verifier.py`:
    - Verifies linear event chain hash, binary Merkle tree root, manifest hash, and Ed25519 digital signature.
    - Integrated with `KeyRegistry`: immediately rejects packages signed with revoked keys (`KEY_REVOKED`), verifies public key parity, and supports enforcing active-only keys.
    - Added `verify_event_inclusion` method to verify specific events within evidence packages.
    - Updated CLI to accept `--keyring <file.json>` and `--enforce-active`.
- [x] **4.5 Evidence API Endpoints**:
  - Added public key discovery and lifecycle endpoints to `backend/app/api/endpoints/evidence.py`:
    - `GET /api/evidence/keys`: lists all registered public keys and active key ID (never exposes private keys).
    - `GET /api/evidence/keys/{key_id}`: returns metadata for a specific key.
    - `POST /api/evidence/keys/rotate`: rotates to a fresh signing key.
    - `POST /api/evidence/keys/{key_id}/revoke`: revokes a key with reason.
  - Updated `POST /api/evidence/verify` to validate packages against `get_active_key_registry()`.
- [x] **4.6 Key Security & Git Protection**:
  - Added `*.pem`, `*.key`, `.keys/`, and `backend/.keys/` to `.gitignore` to guarantee signing keys are never committed to git.
- [x] **4.7 Phase 4 Test Suite**:
  - Created `backend/tests/test_phase4_cryptography.py` with 17 tests covering: Merkle tree construction, multi-event inclusion proofs, event order sensitivity, key registry initialization, key rotation, key revocation, keyring export/import, PEM file loading, evidence package signing & standalone verification, trace tampering detection, manifest tampering detection, response text tampering detection, signature bit-flip detection, revoked key rejection, and all evidence key API endpoints.
  - All 17 tests pass. Full test suite: **136 passed, 1 skipped, 0 failed in 6.93s**.

---

## 9. Phase 5 Detailed Execution Log

- [x] **5.1 Target A Session Isolation & Defense Telemetry**:
  - Replaced shared mutable `_mitigation_enabled` global dependency with per-session evaluation via `x-session-id` and `x-mitigation-enabled` HTTP headers.
  - Implemented real input defense firewall: when mitigation is active, detected prompt injections append `input_defense_triggered` event with `session_id`, log structured refusal, and return sanitized response.
  - Implemented real output canary scrubber: when mitigation is active, detected canary leaks append `output_filter_triggered` event with `session_id` and mask tokens.
  - Handled FastAPI dependency fallback so direct Python function calls without HTTP request headers preserve backwards compatibility.
- [x] **5.2 Target B Session Isolation, Real BOLA Defense & RBAC Clearance**:
  - Replaced shared mutable `_mitigation_enabled` with per-session evaluation via `x-session-id`, `x-mitigation-enabled`, `x-user-role`, and `x-customer-id` HTTP headers.
  - Real SQLite BOLA tool rejection: when mitigation is active and a customer queries cross-tenant invoices, target logs `BOLA_VIOLATION` to `enforcement_log` SQLite table, logs structured execution events, and returns strict 403-style refusal.
  - Honest unmitigated breach: when mitigation is disabled, target queries `fetch_invoice_records` and honestly leaks cross-tenant invoices without synthetic evasion.
  - Dynamic RBAC clearance filtering: RAG documents categorized as `RESTRICTED_CONFIDENTIAL` are filtered unless the authenticated `user_role` has clearance (e.g. `admin`, `auditor`, `compliance`).
- [x] **5.3 Third-Party LangChain Target Isolation**:
  - Added missing `import time` in `backend/third_party_targets/agent.py`.
  - Updated `/chat` endpoint to parse `x-session-id` and `x-mitigation-enabled` headers.
  - Passed `mitigation_enabled` parameter to `get_invoice_tool` to enforce real tenant validation per-session without mutating global state.
- [x] **5.4 Conversational Memory Boundary Isolation**:
  - Updated `StatefulMemoryAgent.execute_turn` in `backend/app/bench/targets.py` to accept and key conversation memory strictly by `session_id` instead of a shared global user ID.
  - Enforced memory privilege escalation block: under mitigation (`mitigation_enabled=True`), memory writes attempting role escalation (e.g., `role: admin`, `elevate privileges`) are blocked, preventing multi-turn prompt injection privilege escalation across sessions.
- [x] **5.5 Adaptive Scan Controller Session & Mitigation Propagation**:
  - Updated `AdaptiveScanController` in `backend/app/core/adaptive_controller.py` to accept `mitigation_enabled` parameter.
  - In `_interact_with_target`, propagates `x-session-id`, `x-mitigation-enabled`, and `x-customer-id` headers to downstream target HTTP requests.
  - Updated response event parsing to support both `response_text` / `response` and `execution_trace.events` / `execution_events`.
  - Updated `backend/app/api/endpoints/scans.py` to pass `request.mitigation_enabled` to `AdaptiveScanController`.
- [x] **5.6 Phase 5 Test Suite**:
  - Created `backend/tests/test_phase5_honest_targets.py` with 10 unit and integration tests:
    - `test_target_a_isolated_mitigation_header`: verified session-specific mitigation activation via header.
    - `test_target_a_concurrent_sessions_independence`: verified concurrent session isolation with different mitigation states.
    - `test_target_b_bola_mitigated_enforcement_log`: verified real SQLite `enforcement_log` recording on blocked BOLA requests.
    - `test_target_b_bola_unmitigated_breach_honesty`: verified unmitigated cross-tenant invoice leakage against real SQLite records.
    - `test_target_b_concurrent_sessions_isolated_mitigation`: verified concurrent Target B sessions do not leak mitigation state.
    - `test_target_b_rbac_clearance_filtering`: verified RBAC clearance role filtering for confidential documents.
    - `test_langchain_target_session_isolated_mitigation`: verified LangChain tool mitigation is per-session.
    - `test_stateful_memory_session_boundary_isolation`: verified conversational memory does not leak across session IDs.
    - `test_stateful_memory_mitigation_blocks_escalation`: verified memory-driven privilege escalation is rejected when mitigated.
    - `test_adaptive_controller_session_headers_transmitted`: verified adaptive controller transmits session headers.
  - All 10 tests pass. Full test suite: **146 passed, 1 skipped, 0 failed in 7.66s**.

---

## 10. Phase 6 Detailed Execution Log

- [x] **6.1 README Documentation Honesty & Claim Purification**:
  - Removed all unsupported claims ("100% precision, 100% recall" as a general platform capability, "compliant with OWASP/ATLAS/NIST", unverified Jira/Slack production webhooks, fake Chroma embeddings).
  - Explicitly marked telemetry trust levels: L0 (Black-Box Text) and L1 (Target Instrumented Traces) as "Implemented"; L2 (Proxy-Observed Sidecar) and L3 (Hardware Attested Sandbox) as "Roadmap (Phase 8)".
  - Honestly labeled RAG architecture as "Local TF-IDF Vector RAG Index (Cosine Similarity)" rather than Chroma.
  - Linked all empirical figures to committed JSON artifacts under `backend/app/bench/results/` with two-sided 95% Wilson score confidence intervals.
  - Updated test badge to 154 passed.
- [x] **6.2 Framework & Compliance Mapping Artifact**:
  - Created `docs/COMPLIANCE_MAPPING.md` providing an exhaustive per-control technical crosswalk.
  - Mapped to OWASP Top 10 for LLM Applications (2025) (LLM01, LLM02, LLM06, LLM07, LLM08, LLM10).
  - Mapped to MITRE ATLAS (AML.T0054, AML.T0051, AML.T0057, AML.T0053, AML.T0040).
  - Mapped to NIST AI RMF 1.0 (GOVERN 1.2, MAP 1.1, MEASURE 2.6, MEASURE 2.7, MANAGE 2.4).
  - Explicitly documents implementation components, exact code and pytest evidence paths, boundaries, and status ("MAPPED & TESTED").
- [x] **6.3 Open-Source Baseline Comparison (`BASELINES.md`)**:
  - Created `BASELINES.md` comparing ShadowBoard against Garak (v0.16.0) and PyRIT (v0.4.0+).
  - Verified Garak installs cleanly via PyPI in standard Python 3.10+ environments.
  - Documented head-to-head empirical comparison across identical targets (Meridian Target A/B) and identical probe categories (Prompt Extraction, Tool-level BOLA, RAG Confidential Retrieval, Benign Refusals).
  - Honestly documented where Garak/PyRIT excels (broad static linguistic jailbreaks, ciphers, multi-turn fuzzing) vs where ShadowBoard excels (execution-aware trace auditing, independent oracle, Merkle tree evidence, CI regression gating).
  - Adhered strictly to the principle of "no manufactured superiority."
- [x] **6.4 Calibrated Benchmark Runner & Artifact Persistence**:
  - Created `backend/app/bench/wilson.py` implementing calibrated two-sided 95% Wilson score confidence intervals with robust edge-case handling ($N=0$, clamping, symmetry).
  - Created `backend/app/bench/runner.py` standardizing benchmark execution, config hashing (SHA-256 fingerprint of probe definitions), git commit SHA recording, latency profiling, and JSON artifact persistence.
  - Created and committed benchmark artifacts under `backend/app/bench/results/`:
    - `benchmark_run_deterministic_vulnerable.json` (600 probes, unmitigated)
    - `benchmark_run_deterministic_mitigated.json` (600 probes, mitigated)
    - `benchmark_run_live_groq_qwen27b.json` (100 live Groq model turns with full Wilson intervals)
  - Created `backend/app/bench/README.md` documenting dependencies, environment variables, exact CLI commands, seed, and schema 2.0.0 specifications.
- [x] **6.5 Phase 6 Dedicated Test Suite**:
  - Created `backend/tests/test_phase6_statistical_honesty.py` with 8 tests:
    - `test_wilson_score_interval_known_values`: validated 95% Wilson bounds against statistical reference values.
    - `test_wilson_score_interval_edge_cases`: validated zero trials, clamping, and symmetry.
    - `test_committed_benchmark_artifacts_exist_and_validate_schema`: validated all committed artifacts adhere to schema 2.0.0 and satisfy $TP + TN + FP + FN == N$.
    - `test_readme_documentation_honesty_and_banned_claims`: asserted zero banned marketing phrases in README.md.
    - `test_framework_mapping_artifact_integrity`: verified completeness of `docs/COMPLIANCE_MAPPING.md`.
    - `test_baselines_documentation_integrity`: verified completeness of `BASELINES.md`.
    - `test_benchmark_readme_documentation_integrity`: verified completeness of `backend/app/bench/README.md`.
    - `test_reproducible_benchmark_runner_execution`: validated mini benchmark run generating dynamic config hash and Wilson CIs.
  - All 8 tests pass. Full test suite: **154 passed, 1 skipped, 0 failed in 11.20s**.

---

## 11. Phase 7 Detailed Execution Log

- [x] **7.1 Banned Hardcoded Values Purged**:
  - Swept and purged hardcoded benchmark strings (`1042`, `$12,850`, `INTERNAL_DOC_7C15`, and specific tool name `get_invoice`) from `backend/app/verifier/engine.py`, `backend/app/verifier/execution_evaluator.py`, and `backend/app/api/endpoints/scans.py`.
  - Generalized tenant parameter detection in `PolicyAssertionEngine.audit_trace` across standard tenant keys (`customer_id`, `account_id`, `user_id`, `tenant_id`, `client_id`).
  - Generalized financial amount detection in `ExecutionAwareEvaluator.audit_network_observation` via regex currency pattern matching rather than checking literal float strings.
  - Generalized internal document detection via dynamic prefix patterns (`INTERNAL_DOC_`) rather than hardcoded document numbers.
  - Replaced hardcoded fallback tool name `get_invoice` in `ExecutionAwareEvaluator` with `standard_query`.
  - Verified 0 banned values across `backend/app/verifier/`, `backend/app/api/endpoints/scans.py`, and `backend/app/core/`.
- [x] **7.2 Standalone Audit Tool (`scripts/ci_enforcement_audit.py`)**:
  - Developed standalone CI audit script executing 7 core checks independently of pytest:
    1. Git tracked file hygiene (verifies no tracked `.env`, `.pem`, `.key`, `.db`, `.sqlite`, build artifacts)
    2. Secret pattern scanning (verifies no tracked live API key formats, private key headers)
    3. Banned benchmark value sweep (scans production verifiers, API routers, and core modules)
    4. Alembic absence hygiene (ensures no orphaned empty alembic directories exist)
    5. Frontend entrypoint integrity (checks `App.tsx` imports, `index.html` structure)
    6. Single verdict engine routing (validates `master_verifier` as sole PolicyAssertionEngine authority)
    7. Production Dockerfile configuration (validates non-root user, proper COPY order, and `/api/health` healthcheck endpoint)
- [x] **7.3 Permanent CI Regression Enforcement Test Suite (`backend/tests/test_phase7_permanent_ci_suite.py`)**:
  - Implemented comprehensive automated test suite for all 23 audit invariants:
    - Invariant 1: Clean-install dependencies hygiene
    - Invariant 2: Secret hygiene & pattern sweep
    - Invariant 3: Zero hardcoded benchmark values in production engines & verifiers
    - Invariant 4: Oracle independence & observation tampering invariance
    - Invariant 5: Phase 3 adversarial refusal & leak boundaries
    - Invariant 6: Blocked tool calls can never yield `CONFIRMED` breach
    - Invariant 7: Central admin authentication fail-closed enforcement
    - Invariant 8: Strict CORS wildcard ban
    - Invariant 9: SSRF protection across loopback, RFC1918, link-local, cloud metadata
    - Invariant 10: Target URL authorization & safe redirects
    - Invariant 11: Per-session mitigation isolation
    - Invariant 12: Concurrent scan state isolation
    - Invariant 13: SSE subscriber queue cleanup on scan termination
    - Invariant 14: Scan concurrency cap (max 3 concurrent)
    - Invariant 15: Unsigned evidence packages fail cryptographic verification
    - Invariant 16: Unregistered key_id fails PKI verification
    - Invariant 17: Evidence tampering fails Merkle tree & Ed25519 verification
    - Invariant 18: PolicyAssertionEngine is the sole verdict engine authority
    - Invariant 19: Frontend build integrity & no recursive imports
    - Invariant 20: Production Dockerfile multi-stage build & non-root user
    - Invariant 21: `/api/health` healthcheck endpoint responsiveness
    - Invariant 22: No generated artifacts or databases tracked in Git
    - Invariant 23: Complete absence of orphaned Alembic directories
- [x] **7.4 CI Workflow Integration (`.github/workflows/shadowboard-assurance.yml`)**:
  - Added `Run Permanent CI Regression Enforcement Audit` step (`python scripts/ci_enforcement_audit.py`) to the automated CI pipeline before pytest.
- [x] **7.5 Full Suite Verification**:
  - `python scripts/ci_enforcement_audit.py`: 7/7 checks PASS.
  - `pytest backend/tests/test_phase7_permanent_ci_suite.py`: 23/23 tests PASS.
  - Full suite `pytest backend/tests -v`: **177 passed, 1 skipped, 0 failed in 8.67s**.

---

## 12. Phase 8 Detailed Execution Log

- [x] **8.1 L2 Observation Sidecar Architecture & Data Model**:
  - Implemented `backend/app/sidecar/models.py` defining `NetworkObservationEvent`, `TrafficDirection`, and `SidecarSessionSummary`.
  - Built automatic header credential sanitization (redacting `Authorization`, `X-API-Key`, `Cookie`, `Token` to `[REDACTED]`).
  - Added canonical conversion mapping raw wire captures to ShadowBoard `proxy_network_call` execution events.
- [x] **8.2 Observation Proxy & Interceptor (`backend/app/sidecar/proxy.py`)**:
  - Implemented thread-safe `ObservationProxy` with partitioned session buffers.
  - Implemented async HTTP request forwarding with payload hashing (`forward_and_observe`).
  - Computed session summaries with binary Merkle tree root (`MerkleTree`) and linear event chain hash.
  - Implemented `export_l2_evidence_package` embedding `substrate_truth_level: "PROXY_OBSERVED"` with Ed25519 digital signature.
- [x] **8.3 Standalone ASGI Sidecar Server (`backend/app/sidecar/server.py`)**:
  - Built standalone FastAPI application exposing `/proxy/observe`, `/proxy/sessions/{id}/events`, `/proxy/sessions/{id}/summary`, `/proxy/sessions/{id}/export`, and `/proxy/health`.
- [x] **8.4 Verifier & Evaluation Engine L2 Integration**:
  - Updated `PolicyAssertionEngine.verify` in `backend/app/verifier/engine.py` to audit `proxy_network_call` events and emit `L2_PROXY_OBSERVED` evidence level.
  - Updated `ExecutionAwareEvaluator.audit_trace` in `backend/app/verifier/execution_evaluator.py` to recognize proxy network observations and issue `L2_PROXY_OBSERVED` attestation.
  - Updated `IndependentOracle.evaluate` in `backend/app/bench/oracle.py` to incorporate out-of-band proxy observations into ground-truth evaluation.
- [x] **8.5 Gaslighting & Telemetry Suppression Defeat**:
  - Proved that when an adversarial or uninstrumented target agent claims verbal refusal in text and omits tool call telemetry from its response, the out-of-band proxy captures the wire interaction, proves the BOLA breach, and generates an independently signed evidence package.
  - Proved that when a target hallucinates numbers without wire traffic, the proxy confirms 0 network calls were made.
- [x] **8.6 Dedicated Phase 8 Test Suite (`backend/tests/test_phase8_observation_sidecar.py`)**:
  - All 8 tests pass:
    - `test_sidecar_models_and_sanitization`: verified sanitization and canonical mapping.
    - `test_sidecar_session_isolation_and_buffer_cleanup`: verified per-session buffer isolation.
    - `test_sidecar_session_summary_and_merkle_tree`: verified binary Merkle tree and linear hash chains.
    - `test_l2_evidence_cryptography_and_provenance`: verified offline validation with `StandaloneVerifier`.
    - `test_detect_target_gaslighting_telemetry_suppression`: verified gaslighting defeat across PolicyAssertionEngine, ExecutionAwareEvaluator, and IndependentOracle.
    - `test_detect_target_hallucination_without_network_breach`: verified wire event verification.
    - `test_sidecar_standalone_api_endpoints`: verified FastAPI proxy endpoints.
    - `test_forward_and_observe_mock_http`: verified HTTP forwarding and observation capture.
  - Full test suite: **185 passed, 1 skipped, 0 failed in 9.86s**.

---

## 13. Post-Phase 8 Architectural Remediation & Code-Level Audit Closure

Following an independent code-level audit of the actual codebase, all identified architectural discrepancies were remediated:

- [x] **13.1 Consolidated Sole Verdict Engine Authority**:
  - Added `PolicyAssertionEngine.resolve_verdict(has_violations, is_explicit_refusal, is_inconclusive)` in `backend/app/verifier/engine.py` as the **single source of truth** for security verdicts across the entire platform.
  - Refactored `backend/app/verifier/execution_evaluator.py` to delegate all verdict assignments directly to `master_verifier.resolve_verdict()`; purged all direct `"CONFIRMED"` and `"PASS"` assignments.
  - Refactored `backend/app/policy_engine/evaluator.py` to route all rule and policy evaluation verdicts through `master_verifier.resolve_verdict()`.
  - Strengthened `test_invariant_18_exactly_one_verdict_engine` in `backend/tests/test_phase7_permanent_ci_suite.py` to statically and dynamically verify that no module independently mints verdict literals.

- [x] **13.2 Phase 4 Legacy Reference Cleanliness**:
  - Deleted `_DEFAULT_PRIVATE_KEY` and `_get_default_private_key()` from `backend/app/evidence/bundler.py`.
  - Zero hardcoded or default private keys remain in the entire codebase.

- [x] **13.3 Phase 2 Residual Hardcoded Demo Values Purged from General Paths**:
  - `backend/app/verifier/engine.py`: Replaced hardcoded `POL-LEAK-004` check with generic RAG leak rule matching (`rule_type in ("canary_absence", "rag_tenant_isolation")`, `owasp_category`, `resource`).
  - `backend/app/planner/autonomous_planner.py` & `backend/app/api/endpoints/planner.py`: Replaced hardcoded default tenant `"1042"` with generic `"tenant_target_02"` and user ID with `"user_session_01"`. Replaced hardcoded tool `"get_invoice"` fallback with `"query_tenant_resource"`.
  - `backend/app/bench/targets.py`: Replaced hardcoded `$12,850.00 if target_cid == "1042"` with dynamic seeded database querying against `fetch_invoice_records(get_shared_invoice_db(), target_cid)` and generalized prompt tenant ID extraction with regex.
  - `backend/app/internal_rag/app.py`: Removed hardcoded `"1042"` tenant fallback on audit/compliance queries.
  - Strengthened `test_invariant_3_no_hardcoded_benchmark_values` to verify `backend/app/planner` and `planner.py`.

- [x] **13.4 Oracle Trust Boundary Clarification**:
  - Enforced strict trust boundary in `backend/app/bench/oracle.py` (`evaluate_probe_outcome`):
    - Untrusted target telemetry (L1) cannot unilaterally declare an oracle ground-truth breach.
    - Ground truth is strictly established via caller-observed response matching against the seeded SQLite reference database or authoritative L2 proxy observations (`truth_level == "L2_PROXY_OBSERVED"`).

- [x] **13.5 Real Multi-Process Subprocess End-to-End Test (`test_phase8_real_subprocess_e2e`)**:
  - Added dedicated out-of-process integration test in `backend/tests/test_phase8_observation_sidecar.py`:
    - Spawns real vulnerable target process on an ephemeral localhost port.
    - Spawns real sidecar server process via `uvicorn app.sidecar.server:app` on a separate ephemeral port.
    - Dispatches attack traffic through the sidecar `/proxy/observe` proxy endpoint.
    - Captures request/response, redacts credentials, and exports an Ed25519-signed L2 evidence package.
    - Evaluates Independent Oracle verdict on authoritative L2 proxy evidence.
    - **Terminates and kills the target subprocess** (simulating target crash, evasion, tampering).
    - Verifies that post-death cryptographic evidence and attestation verification remain **100% valid**.

- [x] **13.6 CI & Test Suite Verification**:
  - `python scripts/ci_enforcement_audit.py`: **7/7 PASS**.
  - `pytest backend/tests/test_phase8_observation_sidecar.py -v`: **9/9 PASS**.
  - `pytest backend/tests/test_phase7_permanent_ci_suite.py -v`: **23/23 PASS**.
  - Full suite `pytest backend/tests`: **186 passed, 1 skipped, 0 failed in 9.21s**.



