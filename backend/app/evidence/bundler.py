"""Independently Verifiable Evidence System — Bundler.

Produces reproducible, cryptographically sealed evidence packages for every security violation:
- Integrity: Linear SHA-256 Merkle chain over execution events + canonical manifest hash
- Authenticity: Asymmetric digital signature (Ed25519 RFC 8032) using private signing key
- Substrate Truth: Explicit declaration of evidence telemetry provenance
  (TARGET_INSTRUMENTED | PROXY_OBSERVED | SYNTHETIC)
"""

from typing import Dict, Any, List, Optional
import hashlib
import json
import time
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from app.evidence.merkle import MerkleTree
from app.evidence.key_registry import get_active_key_registry, KeyRecord


def canonical_hash(obj: Any) -> str:
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_event_chain_hash(events: List[Dict[str, Any]]) -> str:
    """Computes a linear Merkle-like hash chain over an execution event sequence for data integrity."""
    if not events:
        return hashlib.sha256(b"EMPTY_TRACE").hexdigest()
    
    current_hash = hashlib.sha256(b"GENESIS").hexdigest()
    for ev in events:
        ev_hash = canonical_hash(ev)
        combined = f"{current_hash}:{ev_hash}"
        current_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
    return current_hash


class CryptographicProof(BaseModel):
    # 1. Integrity (detects bit tampering and reordering)
    integrity_algorithm: str = "SHA256-MERKLE-CHAIN-V1"
    event_chain_hash: str
    event_merkle_root: str = ""
    manifest_hash: str
    canonical_payload_hash: str

    # 2. Authenticity (asymmetric Ed25519 digital signature proving non-repudiation and origin)
    authenticity_algorithm: str = "ED25519-RFC8032"
    signature_ed25519_hex: str
    signer_public_key_hex: str
    key_id: str = "sb_key_primary"
    
    # Backward compatibility field (legacy alias for canonical_payload_hash)
    package_signature: str = ""

    # 3. Substrate Truth (identifies telemetry provenance)
    substrate_truth_level: str = "TARGET_INSTRUMENTED"  # TARGET_INSTRUMENTED | PROXY_OBSERVED | SYNTHETIC
    timestamp_utc: float = Field(default_factory=time.time)


class EvidencePackage(BaseModel):
    package_id: str
    scan_id: int
    target_id: int
    target_name: str
    finding_id: str
    rule_id: str
    rule_name: str
    severity: str
    owasp_category: str
    taxonomy_version: str = "2025"

    attack_vector: str
    attack_prompts: List[str]
    strategies_used: List[str]

    target_mode: str
    response_text: str
    execution_events: List[Dict[str, Any]]
    
    violation_details: Dict[str, Any]
    remediation_recommendation: str
    remediation_code_patch: str

    proof: CryptographicProof

    def to_json(self) -> str:
        return json.dumps(self.model_dump(), indent=2, sort_keys=True)


class EvidenceBundler:
    """Creates independently verifiable evidence packages with Ed25519 digital signatures and KeyRegistry."""

    @classmethod
    def create_package(
        cls,
        scan_id: int,
        target_id: int,
        target_name: str,
        finding_id: str,
        rule_id: str,
        rule_name: str,
        severity: str,
        owasp_category: str,
        attack_prompts: List[str],
        strategies_used: List[str],
        response_text: str,
        execution_events: List[Dict[str, Any]],
        violation_details: Dict[str, Any],
        remediation_text: str,
        target_mode: str = "INSTRUMENTED",
        code_patch: Optional[str] = None,
        signing_key: Optional[ed25519.Ed25519PrivateKey] = None,
        key_id: Optional[str] = None,
        substrate_truth_level: str = "TARGET_INSTRUMENTED",
    ) -> EvidencePackage:
        pkg_id = f"SBEV-{int(time.time())}-{finding_id[-8:]}"

        # 1. Compute Integrity Hashes (Linear Merkle chain + Binary Merkle tree root)
        event_chain_hash = compute_event_chain_hash(execution_events)
        event_merkle_root = MerkleTree(execution_events).root

        manifest_data = {
            "pkg_id": pkg_id,
            "scan_id": scan_id,
            "target_id": target_id,
            "rule_id": rule_id,
            "finding_id": finding_id,
        }
        manifest_hash = canonical_hash(manifest_data)

        combined_payload = {
            "manifest_hash": manifest_hash,
            "event_chain_hash": event_chain_hash,
            "response_hash": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
            "violation": violation_details,
        }
        canonical_payload_hash = canonical_hash(combined_payload)

        # 2. Key Registry & Authenticity: Sign the canonical payload hash with real Ed25519 private key
        registry = get_active_key_registry()
        if signing_key:
            key = signing_key
            effective_key_id = key_id or "custom_ephemeral_key"
        else:
            key, registered_kid = registry.get_active_signing_key()
            effective_key_id = key_id or registered_kid

        public_key = key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        signer_public_key_hex = pub_bytes.hex()

        # Ensure public key is registered in registry
        if not registry.get_key(effective_key_id):
            registry.register_public_key(
                KeyRecord(
                    key_id=effective_key_id,
                    public_key_hex=signer_public_key_hex,
                    status="ACTIVE",
                    description="Evidence signing key",
                )
            )

        # Ed25519 signs the canonical payload bytes
        sig_bytes = key.sign(canonical_payload_hash.encode("utf-8"))
        signature_ed25519_hex = sig_bytes.hex()

        proof = CryptographicProof(
            integrity_algorithm="SHA256-MERKLE-CHAIN-V1",
            event_chain_hash=event_chain_hash,
            event_merkle_root=event_merkle_root,
            manifest_hash=manifest_hash,
            canonical_payload_hash=canonical_payload_hash,
            authenticity_algorithm="ED25519-RFC8032",
            signature_ed25519_hex=signature_ed25519_hex,
            signer_public_key_hex=signer_public_key_hex,
            key_id=effective_key_id,
            package_signature=canonical_payload_hash,  # Backward compatibility
            substrate_truth_level=substrate_truth_level,
        )

        default_patch = (
            "# Code Remediation Patch (Server-Side Session Validation)\n"
            "def handle_tool_call(tool_name, arguments, session_context):\n"
            "    # Reject caller arguments that attempt to cross tenant boundaries\n"
            "    if 'customer_id' in arguments:\n"
            "        arguments['customer_id'] = session_context.authenticated_customer_id\n"
            "    return execute_under_sandbox(tool_name, arguments)\n"
        )

        return EvidencePackage(
            package_id=pkg_id,
            scan_id=scan_id,
            target_id=target_id,
            target_name=target_name,
            finding_id=finding_id,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            owasp_category=owasp_category,
            attack_vector=rule_id,
            attack_prompts=attack_prompts,
            strategies_used=strategies_used,
            target_mode=target_mode,
            response_text=response_text,
            execution_events=execution_events,
            violation_details=violation_details,
            remediation_recommendation=remediation_text,
            remediation_code_patch=code_patch or default_patch,
            proof=proof,
        )
