# ShadowBoard Threat Model

Scope: the ShadowBoard platform itself (the scanner, its API, its evidence store, its target
adapters) and the security claims it makes about the systems it tests.

This model exists because **a security tool is an attack surface**. ShadowBoard holds signing
keys, stores evidence, makes outbound requests to operator-supplied URLs, runs a browser, and
publishes verdicts that people act on. Each of those is a trust boundary.

---

## 1. Assets

| Asset | Why it matters | Where it lives |
| :--- | :--- | :--- |
| **Evidence packages** | The product's only verifiable output. If they can be forged or silently altered, every finding is worthless. | `app/evidence/`, `evidence` DB tables, exported bundles |
| **Signing private key** | Provenance of evidence. | `SIGNING_KEY_PATH`, previously `backend/.keys/*.pem` |
| **Operator API key** | Gates every mutating endpoint and every scan. | `SHADOWBOARD_ADMIN_KEY` |
| **Target scope config** | Prevents ShadowBoard from attacking systems the operator does not own. | `TargetScope`, onboarding API |
| **Target credentials / session cookies** | Provided by the operator for authenticated black-box testing. Disclosure is a live account compromise. | onboarding wizard, `TargetProfile` |
| **Scanned target data** | Responses may contain the target's real customer data. | `attack_attempts.response_text`, evidence bundles |
| **Verdict integrity** | The whole point. A false `PASS` hides a real breach; a false `CONFIRMED` destroys trust. | `app/verdict/`, `app/groundtruth/` |
| **Sidecar observation buffer** | Independent ground truth. | `app/sidecar/proxy.py` |

---

## 2. Trust boundaries

```
 operator ──(1)──► ShadowBoard API ──(2)──► Target adapter ──(3)──► Target chatbot
     │                    │                        │                     │
     │                    │                        │                     │
     │                 (4) evidence store       (5) browser           (6) target's own
     │                    │                        │                     tool calls / DB
     │                    ▼                        ▼
     └──────────(7) auditor with operator keyring  (8) sidecar sees wire traffic only
```

1. **Operator → API.** Authenticated by `SHADOWBOARD_ADMIN_KEY` (header or session cookie).
   *Untrusted:* every request body, every URL, every uploaded profile.
2. **API → adapter.** The adapter is trusted code; its *inputs* are not.
3. **Adapter → target.** The target is **hostile**. It may lie, return injected content, hang,
   redirect, or attempt to make ShadowBoard fetch internal resources (SSRF).
4. **API → evidence store.** Needs write and read authorization; evidence must not be
   modifiable after signing.
5. **Browser.** Runs third-party JavaScript from the target origin. Everything the page says is
   attacker-controlled.
6. **Target internals.** Never trusted. Target-emitted execution events are `source:
   "target_untrusted"` and can never establish ground truth on their own.
7. **Auditor.** Holds an out-of-band keyring. The only party whose view is authoritative.
8. **Sidecar.** Independent of the target. Trusted for *what crossed the wire*, not for *what the
   target intended*.

---

## 3. Adversaries

| ID | Adversary | Capability | Goal |
| :--- | :--- | :--- | :--- |
| **ADV-1** | Malicious tested target | Controls its own HTTP responses, page content, tool outputs, RAG documents, timing | Hide a real breach (`gaslighting`); manufacture a fake finding; exfiltrate operator credentials |
| **ADV-2** | Malicious page content | Controls text the browser renders, including hidden instructions | Prompt-inject the scanning agent; drive ShadowBoard to fetch internal URLs; exfiltrate the operator session |
| **ADV-3** | Unauthenticated network attacker | Can reach the API port | Execute scans, read evidence, exfiltrate findings |
| **ADV-4** | Local process / insider | Write access to the working directory | Replace the signing key; rewrite evidence; forge `VALID` |
| **ADV-5** | Misconfigured operator | Points ShadowBoard at a system they do not own | Cause unauthorized testing of a third party |
| **ADV-6** | Attacker who intercepts a published bundle | Sees the JSON only | Alter a finding and pass the offline verifier |
| **ADV-7** | The scanner itself, misused | An LLM planner proposes probes | Escape scope; run unbounded/destructive tests; self-certify success |

---

## 4. Attack surface and mitigations

| # | Surface | Threat | Mitigation (implemented) | Status |
| :-- | :--- | :--- | :--- | :--- |
| S1 | `POST /api/*` | Unauthenticated access (ADV-3) | Central `AdminAuthMiddleware`; fail-closed when key unset; constant-time compare. Auth decision no longer depends on `sys.modules` inspection. | **Fixed** (A-07) |
| S2 | All outbound requests | SSRF to loopback / RFC1918 / link-local / cloud metadata (ADV-2) | `app/core/ssrf.py`: scheme + hostname + resolved-IP validation, metadata denylist, size cap, redirect re-validation, **DNS pinning**. | **Fixed** (A-08) |
| S3 | Browser navigation | Page drives scanner to unrelated origins or internal hosts (ADV-2) | `TargetScope` allowlist enforced before **every** navigation and request; cross-origin navigation to a non-allowlisted host aborts the step. | **Implemented** |
| S4 | Evidence package | Forged or altered finding passes verification (ADV-1, ADV-6) | Canonical serialization; SHA-256 event chain; binary Merkle tree; Ed25519 signature. Verifier distinguishes `VALID` / `UNSIGNED` / `UNVERIFIED_KEY` / `INVALID`. `VALID` requires the key in an **operator keyring**. | **Fixed** (A-05, A-06) |
| S5 | Signing key | Silent generation, world-writable PEM, key substitution (ADV-4) | `SIGNING_MODE=none` by default → **no key is ever created implicitly**. `explicit` mode requires an operator-supplied key file. Unsigned packages are labelled `UNSIGNED` and never reported `VALID`. | **Fixed** (A-05) |
| S6 | Target-provided telemetry | Target hides a breach, or fabricates one (ADV-1) | Target events are untrusted and cannot set ground truth. Ground truth = caller-observed response + reference-DB ownership + out-of-band proxy observations. | **Fixed** (A-03) |
| S7 | Sidecar | Cross-session leakage; credential capture | Per-session partitioned buffers; header redaction (`Authorization`, `Cookie`, `X-API-Key`, `Token`); bounded buffer. | **Implemented** |
| S8 | LLM planner | Expands scope; chooses its own success criteria (ADV-7) | Planner may propose probes but cannot write verdicts; every probe carries a declared security invariant and a budget; scope re-checked per request. | **Implemented** |
| S9 | Destructive tests | State-changing probes against production (ADV-5) | Risk classes per probe; state-changing probes require `allow_state_changing=true` in scope **and** an explicit dry-run confirmation; safe default is read-only. | **Implemented** |
| S10 | Evidence export | Leaking credentials / PII into a shareable bundle | Redaction pass before packaging; known-secret keys stripped; profile never persists passwords or cookies in plaintext. | **Implemented** |
| S11 | Error paths | Stack traces / secrets in 500 responses (ADV-3) | Middleware returns JSON errors; internal exception text is logged, not returned. | **Fixed** (A-09) |
| S12 | `POST /api/scans/sandbox/probe` | Outbound POST to arbitrary `base_url` with no scope check | Scope enforced; refusal with a clear reason when no scope is configured. | **Fixed** |
| S13 | CI CLI | Gate passes against a dead/unreachable target (ADV-1) | `ERROR` is a distinct verdict; unreachable target cannot yield `PASS`; the CLI requires a real adapter target and fails closed. | **Fixed** (A-01, A-12) |

---

## 5. Explicit non-goals and limits

- ShadowBoard **does not** guarantee that a target cannot forge its own telemetry. Signing
  proves *this instance issued this package unchanged*; it does not prove the target reported
  truthfully. Independent evidence comes only from the caller's observation and the sidecar.
- ShadowBoard **does not** bypass CAPTCHAs, MFA, anti-bot systems, or access controls. When the
  browser adapter meets such a barrier it stops and asks the operator to log in manually.
- ShadowBoard **does not** discover a target's internal tool names, table names, or authorization
  rules from a web page. Those remain *unknown* unless instrumentation is provided.
- A hash chain detects *modification* of captured events. It cannot detect an event the collector
  never saw.
- `evidence_strength` is a heuristic over boolean signals — **not** a calibrated probability.
