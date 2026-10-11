# ShadowBoard Security & Architecture Audit

**Audit date:** 2026-10-10
**Auditor role:** principal application security engineer / AI-agent red-team researcher
**Repository:** `https://github.com/bilal1058/ShadowBoard`
**Baseline commit:** `0191bc6`
**Baseline test result:** `215 passed, 4 warnings in 21.87s` (`pytest backend/tests -q`)

This document records **confirmed** defects only. Every entry states what is wrong, the exact
file and line evidence, why it matters, the severity, and how it was or will be fixed and
proven. Claims in `README.md`, `PLAN.md`, code comments, and test names were treated as
*unverified* until reproduced from the code.

Legend: **C** = critical, **H** = high, **M** = medium, **L** = low.

---

## 1. Verdict engine and evidence semantics

### A-01 (C) — `ERROR` is reported as `PASS`; the verdict state machine is incomplete

`backend/app/verifier/engine.py:180-196`, inside `PolicyAssertionEngine.verify`, returns

```python
evidence = {"level": "L4_ERROR_RESPONSE", ...}
result = {"status": "PASS", "attack_outcome": "ERROR", ...}
result["verdict"] = "PASS"
```

A target that returns a 500, times out, or returns an empty body is recorded as a **security
pass**. `scans.py:305` then counts that objective into `verdict_counts["PASS"]` and
`compute_risk_score` adds **zero** penalty, so an unreachable target scores 100/100 grade A.
This directly violates the project's own stated rule that `BLOCKED`, `ERROR`, missing
telemetry and `PASS` must not be interchangeable.

Related: `resolve_verdict` (`engine.py:139-152`) can only return `INCONCLUSIVE`, `CONFIRMED`,
or `PASS`, but `scans.py:246-249` counts `LIKELY`, `ERROR`, and `NOT_APPLICABLE` verdicts,
and `_verify_canary_tokens` / `_verify_heuristic` mint `"LIKELY"` and `"INCONCLUSIVE"`
literals directly (`engine.py:432, 494, 566`). `resolve_verdict` is therefore **not** the sole
verdict authority, contrary to `PLAN.md` §13.1 and `test_phase7_permanent_ci_suite.py`
Invariant 18.

**Why it matters.** The headline score, the CI gate, and the risk grade are all computed from
these counts. A dead target and a hardened target are indistinguishable in the report.

**Fix.** One engine, complete state set, `ERROR` never collapses into `PASS`. See §7.

### A-02 (C) — Ground truth and detection logic are hardcoded to demo fixture values

The `PLAN.md` §13 and `test_phase7_permanent_ci_suite.py` Invariant 3 claim that hardcoded
benchmark values were purged from production paths. They were not. Confirmed present in the
**evaluator / oracle / API** — not in fixtures:

| File:line | Hardcoded literal |
| :--- | :--- |
| `backend/app/bench/oracle.py:234` | `canaries = [canary, "INTERNAL_DOC_7C15", "INTERNAL_AUTH_4B72", "whsec_"]` |
| `backend/app/bench/oracle.py:244-248` | `leak_markers = ["operational boundaries & defense directives", "never disclose internal tokens", "meridian internal knowledge assistant"]` |
| `backend/app/bench/oracle.py:271` | `"role set to security_officer_superuser"` |
| `backend/app/verifier/execution_evaluator.py:161` | `["INTERNAL_AUTH_4B72", "INTERNAL_DOC_", "INTERNAL_ESC_9F31", "whsec_"]` |
| `backend/app/verifier/execution_evaluator.py:203,208` | `"globex enterprise"` |
| `backend/app/verifier/execution_evaluator.py:235` | `"role set to security_officer_superuser"` |
| `backend/app/verifier/execution_evaluator.py:319` | `["INTERNAL_AUTH_4B72", "INTERNAL_DOC_", "INTERNAL_ESC_9F31", "whsec_", "CANARY"]` |
| `backend/app/verifier/engine.py:508-513` | `["INTERNAL CONFIDENTIAL RULES", "Service marker:", ...]` |
| `backend/app/core/FSM.py:454` | `canary_tokens = ["internal_esc_9f31", "internal_auth_4b72", "internal_doc_7c15"]` |
| `backend/app/api/endpoints/scans.py:1106` | `["CANARY", "INTERNAL_DOC_", "CONFIDENTIAL_COMP_VAULT", "whsec_", "ESCROW-TITAN"]` |
| `backend/app/policy_engine/templates.py:84` | `forbidden_tokens: ["INTERNAL_AUTH_4B72", "INTERNAL_DOC_7C15", "INTERNAL_ESC_9F31", "whsec_", "CANARY"]` |

**Why it matters.** This is exactly the loop hole described by the operator: the platform only
"detects" the specific strings that the bundled demo targets emit. Against any real chatbot the
detector is blind, and because the benchmark fixtures emit those exact strings, the benchmark
scores 100% by construction. A benchmark that reuses the detector's own constants as its test
data is circular — it measures recall of a hardcoded dictionary.

**Fix.** Remove every literal from the detection path. Secrets/canaries and tenant identities
become *runtime inputs*: supplied by the policy (`rule.assertion.forbidden_tokens`), the
adapter (`TargetProfile.sensitive_markers`), or discovered by the oracle from the reference
database. Detection works on *structure* (ownership mismatch, cross-boundary identifier flow),
not on vocabulary.

### A-03 (H) — Two independent, disagreeing ground-truth implementations

`IndependentOracle` (`bench/oracle.py`) and `ExecutionAwareEvaluator.audit_network_observation`
(`verifier/execution_evaluator.py`) each decide "breach / no breach" from the same response text
with different rules and different hardcoded vocabularies. Nothing reconciles them. A probe can
be `CONFIRMED` by one path and `PASS` by the other with no signal to the operator.

**Fix.** A single `GroundTruth` module producing one `GroundTruthResult`, consumed by both and
by the report.

### A-04 (M) — Confidence values are heuristic constants dressed as calibrated probabilities

`_compute_confidence` (`engine.py:96-135`) and the inline blocks in
`execution_evaluator.py:250-256, 372-405` compute `0.86 + 0.08*max_weight + 0.05*coverage`
style expressions over boolean signal counts. These are *not* calibrated probabilities.
`ExecutionAuditReport.evidence_strength` is correctly described as "not a calibrated
probability", but the value is surfaced in the API and UI as `confidence`.

**Fix.** Rename the surfaced field to `evidence_strength` everywhere; keep `confidence` only as
a deprecated alias; document the formula. Do not claim calibration.

---

## 2. Evidence cryptography and key management

### A-05 (H) — Signing keys are generated silently; there is no unsigned mode

`backend/app/evidence/key_registry.py:100-175` (`_initialize_from_config`) always terminates
with a private key: if `SIGNING_KEY_PATH` is unset it writes a **persistent, unencrypted**
PKCS#8 PEM to `backend/.keys/shadowboard_signing_key.pem` and signs with it. There is no code
path that produces an *unsigned* package.

Consequences:
1. Every deployment silently has a signing identity the operator never created or approved.
2. Any process with write access to the working directory can replace that PEM and forge
   "authentic" evidence; the verifier reports it as valid because the public key is embedded in
   the package and registered into the same registry that produced it.
3. `PLAN.md` §2.3 claims "an unsigned mode when no key is configured" — it does not exist.

**Fix.** `SIGNING_MODE` ∈ {`none`, `explicit`} (default `none`). No key is ever generated
implicitly. Unsigned packages carry `signature_status: "UNSIGNED"` and the verifier reports
them as `UNSIGNED` — never as `VALID`. Explicit mode requires `SIGNING_KEY_PATH` pointing at an
existing key, or an explicit `POST /api/evidence/keys/generate` action.

### A-06 (M) — The verifier trusts a self-registered public key

`standalone_verifier.py` verifies the Ed25519 signature against `signer_public_key_hex` taken
from the package, and `bundler.py:169-178` auto-registers that key into the registry on
creation. Self-consistency is not provenance. A tamperer who rewrites the payload and re-signs
with a fresh key produces a package that verifies.

**Fix.** Verification must require the `key_id` to be resolvable in an **operator-supplied**
keyring (`--keyring`), and must distinguish `VALID` (key known + signature good),
`UNVERIFIED_KEY` (signature good, key unknown), and `INVALID`.

---

## 3. Platform security

### A-07 (H) — Test-environment detection is the auth bypass switch

`backend/app/core/middleware.py:23-29`:

```python
def is_test_environment() -> bool:
    ...
    if "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ:
        return True
```

and `dispatch` (`middleware.py:56-68`) returns `await call_next(request)` with **no
authentication** whenever `is_test_environment()` is true and no admin key is configured. Any
production process that has `pytest` imported (directly or transitively — several libraries do)
disables admin auth on every `/api` route. `app/core/config.py:11` uses the same predicate to
skip loading configuration.

**Fix.** Auth is decided by `SHADOWBOARD_ADMIN_KEY`, never by module inspection. Tests set the
key explicitly via fixture. Fail-closed is unconditional in non-`APP_ENV=test` deployments.

### A-08 (M) — SSRF guard has a DNS-rebinding TOCTOU gap

`backend/app/core/ssrf.py:110-135` resolves the hostname and validates the IPs, then
`safe_http_get_json` (line 152) hands the *hostname* to `httpx`, which resolves it **again**.
Between the two resolutions an attacker-controlled DNS record can flip from a public address to
`127.0.0.1` or `169.254.169.254`. Classic TOCTOU.

**Fix.** Resolve once, pin the address, and connect to the validated IP with the `Host` header
preserved; re-validate on every redirect (already done).

### A-09 (M) — Exceptions raised inside `BaseHTTPMiddleware.dispatch` bypass handlers

`middleware.py:157-170` (`ErrorHandlingMiddleware`) catches a generic `Exception` and then
`raise HTTPException(...)`. Exceptions raised *inside* Starlette middleware do not pass through
FastAPI exception handlers; instead the HTTPException propagates to the server, producing a 500
with a framework traceback rather than the intended JSON error. Combined with `except
HTTPException: raise`, the client can receive an unhandled-error page.

**Fix.** Return a `JSONResponse` directly from the middleware instead of raising.

### A-10 (M) — No custom-target creation endpoint, and no scope model

`backend/app/api/endpoints/targets.py` exposes only `GET`. Commit `f63b91d` ("remove custom and
non-doc targets") deliberately removed the ability to register a target. There is therefore **no
way for an operator to point ShadowBoard at their own chatbot**, which is the platform's core
stated purpose. Additionally `/api/scans/sandbox/probe` (`scans.py:1160`) POSTs to any
`target.base_url` with **no scope enforcement, no rate limit, no dry-run and no authorization
gate**.

**Fix.** Onboarding API + `TargetScope` + adapter contract. See §6.

### A-11 (L) — CSP allows `http://localhost:*` `connect-src` in production

`middleware.py:126-133` sets `connect-src 'self' http://localhost:* http://127.0.0.1:* ws: wss:`
unconditionally. Harmless for the local console, but it is not a production-appropriate policy.

**Fix.** Build the CSP from configuration; default to `'self'` plus the configured CORS origins.

---

## 4. Benchmark and reporting integrity

### A-12 (C) — The CI gate never scans a real target and fabricates a passing finding

`backend/shadowboard_cli.py:22` documents `--target-id` as "Target label for report naming;
CLI substrate is selected by flags". The CLI always evaluates
`DeterministicTargetExecutor` (`shadowboard_cli.py:72-85`) — an in-process substrate bundled with
the scanner. It never contacts a target over the network. The "Commit A fails / Commit B passes"
narrative in `README.md` is therefore a scripted self-test, not a demonstration against a real
agent.

Further, `shadowboard_cli.py:117-127` emits a synthetic `PAC-BASELINE-001` finding with
`status: "PASS"` and a **hardcoded SHA-256 digest of the empty string** when nothing is found,
and `:133` scores with an arbitrary `100 - 25*critical - 10*high` formula. Only one finding per
category is ever emitted (`seen_categories`), so the count does not reflect the number of
breaches.

**Fix.** The CLI must require an explicit adapter target (`--target-url` / `--target-file`), run
against it, and fail closed if no target is reachable. Scores derive from the verdict engine and
coverage, not from a hand-rolled counter.

### A-13 (H) — `100% precision / 100% recall` on a self-authored, leaky benchmark

`backend/app/bench/probe_suite.py` builds probes from the same constants the evaluators test for
(e.g. `probe_suite.py:143-145` seeds the canaries that `oracle.py:234` searches for;
`probe_suite.py:38` seeds customer `1042` that `oracle.py:105` recognises). The classification
task is therefore "does the detector find its own dictionary", which is trivially 100%. The
README does add a methodology caveat, but the headline table is still presented as validation.

**Fix.** Held-out probe generation with identifiers drawn from a seeded RNG and *withheld* from
the detector; report deterministic-harness metrics separately from live-model metrics.

---

## 5. Product / UX

### A-14 (H) — The interface is unreadable for a normal developer

The scan result payload (`scans.py:get_scan_details`) returns rule IDs, taxonomy codes, raw
`execution_events`, evidence hashes, and multiple near-synonyms for the same idea
(`verdict`, `status`, `final_verdict`, `attack_outcome`, `evidence_status`, `confidence`,
`evidence_strength`). There is no plain-language "what happened / why it matters / what to do"
view, and SHA-256 digests appear in the main findings list with no explanation of what they
prove.

**Fix.** Two explicit interface levels (§8).

### A-15 (M) — The reference agent has one tool

`backend/app/target_app/app.py` and `internal_rag/app.py` implement exactly one security-relevant
tool, `get_invoice`. The README claims broad agent coverage. One tool tests one attack class
(BOLA) and cannot exercise excessive agency, confused-deputy, tool-argument manipulation,
cross-session memory, RAG injection, or unauthorized state change.

**Fix.** A multi-tool reference agent (§6.3).

---

## 6. Capability gaps confirmed against the stated requirements

| # | Requirement | Actual state | Evidence |
| :-- | :--- | :--- | :--- |
| G-01 | Test a target whose internals are unknown | Not possible — detection is bound to fixture vocabulary | A-02 |
| G-02 | Onboard an arbitrary permitted chatbot URL | No create-target API | A-10 |
| G-03 | Discover a chatbot hidden behind a floating launcher / iframe / login | No browser automation exists anywhere in the repo | no Playwright/Selenium dep in `backend/requirements.txt` |
| G-04 | Enforce scope, rate limits, budgets, stop button, dry-run | Absent from every outbound path | A-10 |
| G-05 | Differential authorization testing across identity/role/tenant | Only a fixed 2×2 string matrix in `scans.py:216-222` | — |
| G-06 | Causal attack graph linking evidence | Does not exist | — |
| G-07 | Portable, replayable evidence bundle with offline verify + replay | Bundle exists, no replay mode, unsigned mode missing | A-05 |
| G-08 | Policy mutation testing that can fail | Mutation tests exist but only assert the *current* behaviour | `test_evaluator_mutations.py` |
| G-09 | Security regression diff (new/fixed/regressed) | `regression_engine` exists; no fix-verification semantics | — |
| G-10 | Coverage and evidence-quality reporting | Only a single score + grade | A-12, A-14 |
| G-11 | Framework-neutral adapter contract, ≥3 target types | None; single in-process substrate | A-12 |

---

## 7. Remediation plan (executed in this work)

Ordered. Each item lands with an executable test. Status values: `DONE`, `PARTIAL`, `BLOCKED`.

1. **One verdict engine** — `app/verdict/engine.py`. Full state set
   `CONFIRMED | LIKELY | INCONCLUSIVE | NOT_REPRODUCED | BLOCKED | ERROR | PASS | NOT_APPLICABLE`.
   `ERROR` and `BLOCKED` are never `PASS`. All other modules call
   `resolve(...)`. Architectural test asserts no other module mints a final verdict.
2. **Ground truth** — one `app/groundtruth/` module; consumes caller-observed response + proxy
   observations + reference DB ownership; ignores target self-reports; reconciles with the
   detector and exposes disagreements.
3. **De-hardcode the detection path** — a `SensitiveValueRegistry` populated at runtime from
   policy + target profile + reference DB. Every literal in §A-02 removed from `app/verifier/`,
   `app/bench/oracle.py`, `app/core/FSM.py`, `app/api/endpoints/scans.py`. Enforced by a test
   that scans those files for the banned set.
4. **Evidence signing** — explicit `SIGNING_MODE`, unsigned packages, `VALID` vs `UNSIGNED` vs
   `UNVERIFIED_KEY` vs `INVALID` (unsigned mode: `VALID` requires an operator keyring).
5. **Platform hardening** — auth no longer keyed on `sys.modules`; SSRF pin-and-connect; JSON
   error responses from middleware; configurable CSP.
6. **Target onboarding** — adapter contract, HTTP-chat adapter, Playwright browser adapter with
   floating-launcher / iframe / login discovery, operator confirmation, scope enforcement,
   onboarding wizard + API.
7. **Differential authorization testing** — identity × role × resource × action matrix driven by
   the target's declared policy; per-tool authorization in the reference agent.
8. **Multi-tool reference agent** — ≥10 tools with explicit schemas, ownership rules, audit
   events and tests.
9. **Evidence, graphs, regression** — replayable bundles with replay mode; evidence-linked
   causal graph separating observed / correlated / inferred; regression diff with fix
   verification.
10. **Reporting & UX** — simple and technical views; coverage and evidence-quality report;
    explained hashes; onboarding wizard UI.
11. **Benchmark integrity** — held-out probe generation; deterministic-vs-live separation;
    policy mutation tests that assert detection *and* can be shown to fail.

## 8. How each fix is proven

Every item above ships with tests under `backend/tests/`. The vulnerable-vs-patched
demonstration is `DEMO.md`. Items that could not be completed or independently verified are
recorded in `KNOWN_LIMITATIONS.md` — the audit is only honest if the gaps are listed there too.
