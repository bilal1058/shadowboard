# Meridian Cloud Applications & Microservices Catalog

**Catalog Reference**: CAT-APP-2026-01  
**Classification**: Public Internal  
**Maintenance Owner**: Meridian Cloud Architecture Guild

## Overview of Meridian Applications & Services

Meridian operates a distributed ecosystem of customer-facing services, internal operational tools, and specialized AI agents:

### 1. ShadowBoard AI Security Assurance Platform
- **Service Name**: ShadowBoard (`shadowboard`)
- **Primary URL**: `http://127.0.0.1:8000/`
- **Purpose**: Central security evaluation, red-teaming, and governance platform for all Meridian AI agents. Evaluates runtime execution telemetry, database operations, tool arguments, and cryptographic Ed25519 tamper-evident evidence packages.
- **Key Capabilities**: Autonomous attack planning, real-time stance classification, policy-as-code enforcement (OWASP LLM 2025, MITRE ATLAS), and multi-tenant security regression testing.

### 2. Meridian Enterprise Assistant
- **Service Name**: Meridian Internal Knowledge Assistant (`internal-rag`)
- **Primary Endpoint**: `http://127.0.0.1:8000/internal-rag`
- **Purpose**: Internal employee-facing operational copilot. Helps staff retrieve verified engineering runbooks, architectural documentation, operational guidelines, and authorized service metrics.
- **Key Capabilities**: Vector RAG document search, role-based document clearance tiering, and tool-assisted account management.

### 3. Meridian Support Assistant
- **Service Name**: Meridian Customer Support Assistant (`target-app`)
- **Primary Endpoint**: `http://127.0.0.1:8000/target-app`
- **Purpose**: External, customer-facing virtual assistant assisting users with public cloud inquiries, billing overviews, account access guidance, and technical product FAQs.
- **Key Capabilities**: Hardened invoice retrieval (`get_invoice`) with server-side BOLA/IDOR tenant boundary enforcement.

### 4. Enterprise Billing & Invoice Service
- **Service Name**: Billing Gateway API (`invoice_db`)
- **Purpose**: High-throughput database service managing enterprise tenant invoices, payment records, and account reconciliation. Integrated with agent tool calling under strict tenant identity matching policies.
