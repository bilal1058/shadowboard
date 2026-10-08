# Meridian Internal Technical Reference: ShadowBoard AI Security Assurance Platform

## System Overview
ShadowBoard is Meridian's internal execution-aware security assurance platform engineered specifically for tool-using AI agents, Retrieval-Augmented Generation (RAG) pipelines, and enterprise LLM integrations. Unlike conventional red-teaming scanners that rely merely on superficial text output heuristics, ShadowBoard continuously evaluates real execution telemetry, database operations, tool arguments, and cryptographic audit proofs across internal Meridian services.

## Core Platform Architecture
ShadowBoard operates across five core integrated subsystems:

1. **Autonomous Attack Planner & Chaining Engine**:
   - Systematically discovers target tool surfaces, analyzes API schemas, and generates multi-stage attack plans.
   - Probes for Broken Object Level Authorization (BOLA/IDOR), Indirect Vector RAG Prompt Injection, Confused Deputy privileges, and canary secret extraction.

2. **Execution-Aware Runtime Evaluator & Observation Sidecar**:
   - Deployed inline or as a sidecar proxy (`app.sidecar.proxy`) to observe agent execution traces in real time.
   - Evaluates multi-dimensional runtime telemetry: model output refusals, function call arguments, cross-tenant database queries, vector retrieval clearance, and unauthorized outbound egress.
   - Computes deterministic verdicts (DEFENDED, BREACH, PASS) with zero circular evaluation dependencies.

3. **Policy-as-Code Governance Engine**:
   - Enforces declarative security rules mapped directly to OWASP LLM Top 10 (2025), MITRE ATLAS, and NIST AI RMF.
   - Core enterprise policies include:
     - `POL-BOLA-001`: Strict tenant isolation enforcing that session principals only access authorized customer records.
     - `POL-INJ-002`: Untrusted context boundary isolation preventing embedded prompt overrides in retrieved documents.
     - `POL-LEAK-004`: Document clearance tier validation preventing confidential corporate leaks.

4. **Cryptographic Tamper-Evident Evidence Packages**:
   - Signs all execution traces, scan findings, and posture reports using asymmetric Ed25519 digital keys.
   - Constructs RFC 6962 SHA-256 Merkle tree structures ensuring mathematical tamper-evidence and regulatory audit readiness.

5. **Empirical Benchmarking & Statistical Confidence**:
   - Executes systematic probe batteries with Wilson 95% score confidence intervals.
   - Provides live assessment targets including Meridian Support Assistant (Target A, External Support) and Meridian Enterprise Assistant (Target B, Internal Knowledge RAG).
