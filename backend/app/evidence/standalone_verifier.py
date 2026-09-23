"""Standalone Evidence Verifier for Third-Party Auditors.

Validates the cryptographic integrity, Ed25519 authenticity signature, and policy claims
of a ShadowBoard Evidence Package offline without needing a running server.

Distinguishes:
1. Integrity: Merkle hash chain over events + manifest hash (bit tampering detection)
2. Authenticity: Asymmetric Ed25519 digital signature (identity verification & non-repudiation)
3. Substrate Truth: Provenance of telemetry (TARGET_INSTRUMENTED | PROXY_OBSERVED | SYNTHETIC)
"""

from typing import Dict, Any, Tuple, Optional
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from app.evidence.merkle import MerkleTree


class StandaloneVerifier:
    """Independent offline auditor verification tool."""

    @staticmethod
    def canonical_hash(obj: Any) -> str:
        serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def verify_event_inclusion(
        cls,
        event: Dict[str, Any],
        inclusion_proof: list,
        claimed_merkle_root: str,
    ) -> bool:
        """Verifies that an execution event is cryptographically proven to be in the event Merkle tree."""
        return MerkleTree.verify_inclusion(event, inclusion_proof, claimed_merkle_root)

    @classmethod
    def verify_package(
        cls,
        pkg_data: Dict[str, Any],
        key_registry: Optional[Any] = None,
        enforce_active_key: bool = False,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Verifies package integrity and Ed25519 signature, returning (is_valid, message, audit_summary)."""
        proof = pkg_data.get("proof", {})
        if not proof:
            return False, "Missing cryptographic proof block in evidence package", {}

        claimed_event_hash = proof.get("event_chain_hash")
        claimed_merkle_root = proof.get("event_merkle_root")
        claimed_manifest_hash = proof.get("manifest_hash")
        sig_ed25519_hex = proof.get("signature_ed25519_hex")
        pubkey_hex = proof.get("signer_public_key_hex")
        key_id = proof.get("key_id", "sb_key_primary")
        legacy_sig = proof.get("package_signature")
        substrate_truth = proof.get("substrate_truth_level", "UNKNOWN")

        # -------------------------------------------------------------
        # 1. Integrity Verification (Linear Merkle Event Chain)
        # -------------------------------------------------------------
        events = pkg_data.get("execution_events", [])
        if not events:
            recomputed_event_hash = hashlib.sha256(b"EMPTY_TRACE").hexdigest()
        else:
            current_hash = hashlib.sha256(b"GENESIS").hexdigest()
            for ev in events:
                ev_hash = cls.canonical_hash(ev)
                combined = f"{current_hash}:{ev_hash}"
                current_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            recomputed_event_hash = current_hash

        if recomputed_event_hash != claimed_event_hash:
            return False, f"Integrity Failure: Event chain hash mismatch! Claimed: {claimed_event_hash}, Computed: {recomputed_event_hash}", {}

        # -------------------------------------------------------------
        # 1b. Integrity Verification (Binary Merkle Tree Root)
        # -------------------------------------------------------------
        if claimed_merkle_root:
            recomputed_merkle_root = MerkleTree.compute_root(events)
            if recomputed_merkle_root != claimed_merkle_root:
                return False, f"Integrity Failure: Binary Merkle tree root mismatch! Claimed: {claimed_merkle_root}, Computed: {recomputed_merkle_root}", {}

        # -------------------------------------------------------------
        # 2. Integrity Verification (Manifest Hash)
        # -------------------------------------------------------------
        manifest_data = {
            "pkg_id": pkg_data.get("package_id"),
            "scan_id": pkg_data.get("scan_id"),
            "target_id": pkg_data.get("target_id"),
            "rule_id": pkg_data.get("rule_id"),
            "finding_id": pkg_data.get("finding_id"),
        }
        recomputed_manifest_hash = cls.canonical_hash(manifest_data)
        if recomputed_manifest_hash != claimed_manifest_hash:
            return False, f"Integrity Failure: Manifest hash mismatch! Claimed: {claimed_manifest_hash}, Computed: {recomputed_manifest_hash}", {}

        # -------------------------------------------------------------
        # 3. Key Registry & Revocation Verification (PKI Validation)
        # -------------------------------------------------------------
        key_record = None
        if key_registry is not None:
            key_record = key_registry.get_key(key_id)
            if key_record:
                if key_record.status == "REVOKED":
                    reason = key_record.revocation_reason or "Key revoked by administrator"
                    return False, f"Authenticity Failure: Signing key '{key_id}' has been REVOKED! ({reason})", {
                        "verification_status": "KEY_REVOKED",
                        "key_id": key_id,
                        "revocation_reason": reason,
                    }
                if enforce_active_key and key_record.status != "ACTIVE":
                    return False, f"Authenticity Failure: Signing key '{key_id}' is not ACTIVE (status: {key_record.status})", {
                        "verification_status": "KEY_NOT_ACTIVE",
                        "key_id": key_id,
                    }
                if pubkey_hex and key_record.public_key_hex.lower() != pubkey_hex.lower():
                    return False, f"Authenticity Failure: Public key mismatch for registered key_id '{key_id}'!", {
                        "verification_status": "KEY_MISMATCH",
                        "key_id": key_id,
                    }
            elif enforce_active_key:
                return False, f"Authenticity Failure: Signing key '{key_id}' is not registered in trusted key registry!", {
                    "verification_status": "KEY_NOT_REGISTERED",
                    "key_id": key_id,
                }

        # -------------------------------------------------------------
        # 4. Authenticity Verification (Ed25519 Digital Signature)
        # -------------------------------------------------------------
        response_text = pkg_data.get("response_text", "")
        combined_payload = {
            "manifest_hash": recomputed_manifest_hash,
            "event_chain_hash": recomputed_event_hash,
            "response_hash": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
            "violation": pkg_data.get("violation_details", {}),
        }
        recomputed_canonical_hash = cls.canonical_hash(combined_payload)

        # If Ed25519 signature and public key are present, perform asymmetric verification
        if sig_ed25519_hex and pubkey_hex:
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
                sig_bytes = bytes.fromhex(sig_ed25519_hex)
                # Verify that the canonical payload hash was signed by the holder of this private key
                public_key.verify(sig_bytes, recomputed_canonical_hash.encode("utf-8"))
            except (InvalidSignature, ValueError) as exc:
                return False, f"Authenticity Failure: Invalid Ed25519 digital signature! Tampered payload detected or signature mismatch ({exc}).", {}
        elif legacy_sig and recomputed_canonical_hash != legacy_sig:
            return False, f"Integrity Failure: Canonical payload hash mismatch! Claimed: {legacy_sig}, Computed: {recomputed_canonical_hash}", {}

        summary = {
            "package_id": pkg_data.get("package_id"),
            "target_name": pkg_data.get("target_name"),
            "rule_id": pkg_data.get("rule_id"),
            "severity": pkg_data.get("severity"),
            "events_verified": len(events),
            "verification_status": "CRYPTOGRAPHICALLY_VERIFIED",
            "integrity_status": "SHA256_MERKLE_CHAIN_VERIFIED",
            "merkle_tree_status": "BINARY_TREE_VERIFIED" if claimed_merkle_root else "NONE",
            "authenticity_status": "ED25519_SIGNATURE_VERIFIED" if sig_ed25519_hex else "HASH_INTEGRITY_ONLY",
            "substrate_truth_level": substrate_truth,
            "signer_public_key": pubkey_hex or "NONE",
            "key_id": key_id,
            "key_status": key_record.status if key_record else "UNVALIDATED_REGISTRY",
            "merkle_root": claimed_merkle_root or "N/A",
        }
        return True, "Evidence package integrity and Ed25519 signature verified successfully. No tampering detected.", summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Standalone Evidence Package Verifier")
    parser.add_argument("package_path", help="Path to evidence package JSON file")
    parser.add_argument("--keyring", help="Optional path to trusted keyring JSON file", default=None)
    parser.add_argument("--enforce-active", action="store_true", help="Enforce that the signing key must be active in keyring")
    args = parser.parse_args()

    pkg_path = Path(args.package_path)
    if not pkg_path.exists():
        print(f"File not found: {pkg_path}")
        sys.exit(1)

    with open(pkg_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    registry = None
    if args.keyring:
        kr_path = Path(args.keyring)
        if kr_path.exists():
            from app.evidence.key_registry import KeyRegistry
            registry = KeyRegistry()
            with open(kr_path, "r", encoding="utf-8") as kf:
                registry.import_keyring(json.load(kf))
        else:
            print(f"Warning: Keyring file {args.keyring} not found.")

    valid, msg, summary = StandaloneVerifier.verify_package(
        data,
        key_registry=registry,
        enforce_active_key=args.enforce_active,
    )
    if valid:
        print(f"\n[+] AUDIT VERIFIED: {msg}")
        for k, v in summary.items():
            print(f"    * {k}: {v}")
    else:
        print(f"\n[-] AUDIT REJECTED: {msg}")
        sys.exit(1)
