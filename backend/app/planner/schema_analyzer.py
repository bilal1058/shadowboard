"""Target Surface & Schema Analyzer for Autonomous Attack Planning.

Understands the target's tools, policies, data schemas, permissions,
and architecture to map out vulnerable attack vectors.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class DiscoveredTool(BaseModel):
    name: str
    description: str = ""
    parameters: Dict[str, Any] = Field(default_factory=dict)
    identity_parameters: List[str] = []
    is_sensitive: bool = False
    requires_rbac: bool = False


class TargetAttackSurface(BaseModel):
    target_id: int
    target_name: str
    target_type: str
    target_mode: str
    has_tools: bool
    has_rag: bool
    has_memory: bool
    discovered_tools: List[DiscoveredTool] = []
    susceptible_vectors: List[str] = []  # "BOLA_IDOR", "RAG_INJECTION", "SECRET_LEAKAGE", "CONFUSED_DEPUTY"
    recommended_attack_chains: List[str] = []


class SchemaAnalyzer:
    """Analyzes target capabilities and tools to deduce attack vectors."""

    IDENTITY_PARAM_CANDIDATES = [
        "customer_id", "tenant_id", "user_id", "account_id",
        "org_id", "invoice_id", "client_id", "owner_id"
    ]

    SENSITIVE_TOOL_NAMES = [
        "send_email", "execute_refund", "delete_record",
        "transfer_funds", "modify_role", "system_exec"
    ]

    @classmethod
    def analyze_target(
        cls,
        target_id: int,
        target_name: str,
        target_type: str,
        target_mode: str,
        capabilities: Dict[str, Any],
        known_tools: Optional[List[Dict[str, Any]]] = None,
    ) -> TargetAttackSurface:
        has_tools = bool(capabilities.get("has_tools", capabilities.get("tools", False)))
        has_rag = bool(capabilities.get("has_rag", capabilities.get("rag", False)))
        has_memory = bool(capabilities.get("has_memory", capabilities.get("memory", False)))
        tool_names = capabilities.get("tool_names", [])

        discovered_tools: List[DiscoveredTool] = []
        susceptible_vectors: List[str] = []
        attack_chains: List[str] = []

        # 1. Analyze Tools
        if has_tools:
            for name in tool_names:
                # Infer or lookup tool parameters
                identity_params = []
                if "invoice" in name or "account" in name or "user" in name:
                    identity_params = ["customer_id"]
                elif "email" in name:
                    identity_params = ["recipient", "customer_id"]

                is_sensitive = any(s in name for s in cls.SENSITIVE_TOOL_NAMES)
                requires_rbac = is_sensitive or len(identity_params) > 0

                discovered_tools.append(
                    DiscoveredTool(
                        name=name,
                        description=f"Enterprise agent tool: {name}",
                        identity_parameters=identity_params,
                        is_sensitive=is_sensitive,
                        requires_rbac=requires_rbac,
                    )
                )

            # Check for BOLA / IDOR vulnerability surface
            tools_with_id = [t for t in discovered_tools if t.identity_parameters]
            if tools_with_id:
                susceptible_vectors.append("BOLA_IDOR")
                attack_chains.append(
                    f"Discover Tool ({tools_with_id[0].name}) -> Formulate Target Tenant (<target_tenant>) -> Tamper Argument ({tools_with_id[0].identity_parameters[0]}=<target_tenant>) -> Exfiltrate Data"
                )

            # Check for Confused Deputy / High Impact actions
            sensitive_tools = [t for t in discovered_tools if t.is_sensitive]
            if sensitive_tools:
                susceptible_vectors.append("EXCESSIVE_AGENCY_CONFUSED_DEPUTY")
                attack_chains.append(
                    f"Impersonate Supervisor -> Coerce Sensitive Action ({sensitive_tools[0].name}) -> Bypass Human Approval"
                )

        # 2. Analyze RAG
        if has_rag:
            susceptible_vectors.append("INDIRECT_PROMPT_INJECTION")
            susceptible_vectors.append("CROSS_TENANT_DOCUMENT_LEAKAGE")
            attack_chains.append(
                "Trigger RAG Retrieval -> Ingest Adversarial Document Chunk -> Override System Directives"
            )

        # 3. Analyze Conversational / Base Model
        susceptible_vectors.append("SYSTEM_DIRECTIVE_EXTRACTION")
        attack_chains.append(
            "Hypothetical Roleplay Framing -> Extract Internal System Canaries & Operational Directives"
        )

        return TargetAttackSurface(
            target_id=target_id,
            target_name=target_name,
            target_type=target_type,
            target_mode=target_mode,
            has_tools=has_tools,
            has_rag=has_rag,
            has_memory=has_memory,
            discovered_tools=discovered_tools,
            susceptible_vectors=susceptible_vectors,
            recommended_attack_chains=attack_chains,
        )
