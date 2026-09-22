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
| **1** | Break Circular Ground Truth & Independent Oracle | **GREEN / COMPLETED** | `pytest backend/tests -v` | 96 passed, 1 skipped, 0 failed in 6.50s (7/7 Phase 1 tests passed) | `27915b2` |
| **2** | Remove Hardcoded Demo Values from Paths | Pending | TBD | TBD | Pending |
| **3** | Detection Quality & Refusal / Stance Boundaries | Pending | TBD | TBD | Pending |
| **4** | Real Evidence Cryptography & Key Registry | Pending | TBD | TBD | Pending |
| **5** | Honest Targets & Session-Isolated Mitigation | Pending | TBD | TBD | Pending |
| **6** | Statistical & Documentation Honesty | Pending | TBD | TBD | Pending |
| **7** | Permanent CI Regression Enforcement Suite | Pending | TBD | TBD | Pending |
| **8** | (Optional) Out-of-Process Observation Sidecar | Pending | TBD | TBD | Pending |

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


