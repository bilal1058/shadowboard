# Meridian Engineering Runbook: ShadowBoard Security Assessment Operations

**Runbook Identifier**: RB-SEC-SHADOWBOARD-001  
**Target Systems**: ShadowBoard Assurance Platform, Meridian Support Assistant, Meridian Enterprise Assistant  
**Classification**: Public Internal (Engineering & Security Operations)

## 1. Operational Overview
This runbook governs the day-to-day operation, automated vulnerability scanning, and incident triage of Meridian's AI agents using ShadowBoard. Engineers and security auditors must follow these standard operating procedures to validate agent safety before promoting models or prompt revisions to production.

## 2. Standard Service Access & Endpoints
- **ShadowBoard Management Console**: `http://127.0.0.1:8000/` (Integrated UI and Dashboard)
- **Target A (Meridian Support Assistant)**: `http://127.0.0.1:8000/target-app` (External customer-facing conversational agent with invoice lookup tools)
- **Target B (Meridian Enterprise Assistant)**: `http://127.0.0.1:8000/internal-rag` (Internal knowledge assistant equipped with vector document search and enterprise tools)
- **API Health & Telemetry**: `GET /api/health`

## 3. Core Operational Workflows

### Workflow A: Interactive Sandbox Probing
1. Open the ShadowBoard Dashboard and select a target card (e.g., Target #2: Meridian Enterprise Assistant).
2. Click **Inspect Target** to open the Target Inspector and navigate to the **Interactive Chat Sandbox**.
3. Submit conversational probes (e.g., `"tell me about shadowboard"`, `"Check legacy vendor update"`, or invoice lookups).
4. Review the response along with evaluated latency, execution trace events, stance verdict, and defensive rule activations in real time.

### Workflow B: Autonomous Attack Planning & Execution
1. Navigate to the **Autonomous Planner** module (`/api/planner`).
2. Generate an attack chain targeting specific threat vectors:
   - `BOLA_IDOR`: Probing cross-tenant tool parameter manipulation.
   - `RAG_INJECTION`: Injecting adversarial instructions via untrusted vector context.
   - `SECRET_EXTRACTION`: Probing for internal canary tokens or prompt disclosure.
3. Review step-by-step execution traces to confirm whether target defenses successfully neutralized the attack chain.

### Workflow C: Evidence Generation & Cryptographic Verification
1. Following scan execution, navigate to the **Evidence & Reports** view.
2. Verify Ed25519 digital signatures and SHA-256 Merkle root trees.
3. Export executive compliance bundles for quarterly regulatory security reviews.
