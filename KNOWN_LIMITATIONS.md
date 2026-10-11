# ShadowBoard: Known Limitations & Verification Boundaries

In accordance with the mandatory honesty rules, this document records known technical boundaries, environmental constraints, and capabilities that cannot be independently confirmed without appropriate instrumentation.

---

## 1. Black-Box Observation Boundaries

* **Lack of Server-Side Telemetry in Pure Black-Box Mode**:
  When assessing an external chatbot exclusively through its public chat interface (Mode A: Black-Box), ShadowBoard observes only outbound text and visible network traffic. It cannot independently inspect:
  - Internal database SQL queries and table schemas.
  - Server-side tool execution traces and intermediate variables.
  - RAG document chunk embeddings and vector distances.
  
  Consequently, black-box findings that detect foreign entity names in output are graded as `LIKELY` rather than `CONFIRMED`, because the absence of an execution trace prevents mathematically proving internal record ownership without an instrumented adapter.

---

## 2. Cryptographic Signing Claims & Evidence Semantics

* **What Signing Proves**:
  - The evidence package manifest, canonical event hashes, and binary Merkle tree root were signed by the holder of the specified private key.
  - The evidence has not been tampered with or modified in transit after signing.
  - Offline verifiers can detect byte-level modifications and signature bit-flips.

* **What Signing Does NOT Prove**:
  - Digital signatures do not prove that an uninstrumented or compromised target agent truthfully reported all internal events.
  - A signature cannot detect if a target suppressed internal tool execution telemetry prior to emitting its response. To mitigate this limitation, ShadowBoard implements the L2 Out-of-Process Observation Sidecar (`backend/app/sidecar`) to capture independent wire traffic.

---

## 3. Browser Automation & Anti-Bot Restrictions

* **CAPTCHA and Multi-Factor Authentication Barriers**:
  The Playwright browser automation adapter does not attempt to bypass CAPTCHAs, Cloudflare Turnstile, biometric challenges, or multi-factor authentication (MFA). When automation encounters an authentication barrier or login wall, it records `has_login_wall=True` and halts safely, prompting the operator for authorized credentials.

* **Non-Standard Canvas & Shadow DOM Chat Widgets**:
  Chat interfaces rendered entirely inside WebGL/Canvas elements (without accessible DOM roles, accessible names, or semantic `<input>` elements) cannot be reliably manipulated via generic DOM selectors and require operator-supplied custom selector coordinates.

---

## 4. Benchmark Statistical Generalization

* **Controlled Invariants vs. Wild LLMs**:
  Reported precision and recall figures on the 600-probe controlled benchmark represent performance against defined authorization and canary leakage invariants on seeded substrates. They do not guarantee 100% detection accuracy against arbitrary, evolving linguistic jailbreaks on unconstrained external models. Real-world LLM evaluation results are reported with two-sided 95% Wilson score confidence intervals.

---

## 5. Scope Enforcement & Safe Operations

* **Prohibition of Destructive Live Actions**:
  In accordance with safety invariants, state-changing mutations (e.g. permanent account deletion, real payment processing, or live balance transfers) are disabled by default (`disallow_state_changing_actions=True`). Testing against production databases must always use isolated test accounts.
