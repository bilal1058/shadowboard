"""Comprehensive Unit & Integration Test Suite for Phase 4:
Real Evidence Cryptography, Binary Merkle Trees, and Key Registry PKI.
"""

import pytest
import json
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from app.evidence.merkle import MerkleTree
from app.evidence.key_registry import KeyRegistry, KeyRecord, reset_key_registry, get_active_key_registry
from app.evidence.bundler import EvidenceBundler
from app.evidence.standalone_verifier import StandaloneVerifier
from fastapi.testclient import TestClient
from main import app


@pytest.fixture(autouse=True)
def clean_registry():
    """Reset the global key registry before each test to maintain strict isolation."""
    reg = reset_key_registry()
    yield reg
    reset_key_registry()


# =====================================================================
# 1. Binary Merkle Tree & Inclusion Proof Tests
# =====================================================================

def test_merkle_tree_empty_and_single():
    empty_tree = MerkleTree([])
    assert empty_tree.root != ""
    assert len(empty_tree.leaves) == 0

    single_ev = [{"event_type": "tool_call", "action": "read_balance"}]
    single_tree = MerkleTree(single_ev)
    assert len(single_tree.leaves) == 1
    assert single_tree.root != ""

    proof = single_tree.get_inclusion_proof(0)
    assert MerkleTree.verify_inclusion(single_ev[0], proof, single_tree.root) is True


def test_merkle_tree_multi_events_and_inclusion_proofs():
    events = [
        {"seq": 0, "event_type": "request", "prompt": "Show me balance for user 1042"},
        {"seq": 1, "event_type": "policy_check", "status": "FLAGGED"},
        {"seq": 2, "event_type": "tool_call", "tool": "fetch_account", "args": {"id": 1042}},
        {"seq": 3, "event_type": "response", "content": "Account balance $450,000"},
        {"seq": 4, "event_type": "audit_log", "action": "DATA_LEAKED"},
    ]

    tree = MerkleTree(events)
    assert len(tree.leaves) == 5
    root = tree.root
    assert len(root) == 64

    # Verify inclusion proofs for each item in the tree
    for idx, ev in enumerate(events):
        proof = tree.get_inclusion_proof(idx)
        assert len(proof) > 0
        assert MerkleTree.verify_inclusion(ev, proof, root) is True
        assert StandaloneVerifier.verify_event_inclusion(ev, proof, root) is True

    # Tampered event must fail inclusion
    tampered_ev = dict(events[2])
    tampered_ev["args"] = {"id": 9999}
    proof2 = tree.get_inclusion_proof(2)
    assert MerkleTree.verify_inclusion(tampered_ev, proof2, root) is False

    # Proof with modified hash must fail
    bad_proof = [dict(step) for step in proof2]
    bad_proof[0]["hash"] = "0" * 64
    assert MerkleTree.verify_inclusion(events[2], bad_proof, root) is False


def test_merkle_tree_order_sensitivity():
    ev_a = {"id": 1, "type": "event_a"}
    ev_b = {"id": 2, "type": "event_b"}

    tree_1 = MerkleTree([ev_a, ev_b])
    tree_2 = MerkleTree([ev_b, ev_a])

    assert tree_1.root != tree_2.root, "Merkle tree root must be sensitive to event order"


# =====================================================================
# 2. Key Registry & PKI Management Tests
# =====================================================================

def test_key_registry_initialization():
    registry = KeyRegistry()
    priv_key, active_kid = registry.get_active_signing_key()
    assert isinstance(priv_key, ed25519.Ed25519PrivateKey)
    assert active_kid is not None

    record = registry.get_key(active_kid)
    assert record is not None
    assert record.status == "ACTIVE"
    assert record.algorithm == "ED25519"
    assert len(record.public_key_hex) == 64


def test_key_rotation():
    registry = KeyRegistry()
    priv1, kid1 = registry.get_active_signing_key()
    pub1_hex = registry.get_key(kid1).public_key_hex

    # Rotate key
    priv2, rec2 = registry.rotate_key("rotated_key_v2")
    assert rec2.key_id == "rotated_key_v2"
    assert rec2.status == "ACTIVE"

    # Active key must now be rotated_key_v2
    priv_active, kid_active = registry.get_active_signing_key()
    assert kid_active == "rotated_key_v2"
    assert kid_active != kid1

    # Old key must still exist in registry with original public key
    old_rec = registry.get_key(kid1)
    assert old_rec is not None
    assert old_rec.public_key_hex == pub1_hex


def test_key_revocation():
    registry = KeyRegistry()
    _, kid1 = registry.get_active_signing_key()

    # Revoke active key
    revoked_rec = registry.revoke_key(kid1, reason="Private key exposure during security drill")
    assert revoked_rec.status == "REVOKED"
    assert revoked_rec.revoked_at is not None
    assert revoked_rec.revocation_reason == "Private key exposure during security drill"
    assert registry.is_key_revoked(kid1) is True

    # Active key should have automatically rolled over to a fresh key
    _, new_kid = registry.get_active_signing_key()
    assert new_kid != kid1
    assert registry.is_key_active(new_kid) is True


def test_keyring_export_and_import():
    registry1 = KeyRegistry()
    registry1.rotate_key("secondary_key_01")
    registry1.rotate_key("secondary_key_02")
    registry1.revoke_key("secondary_key_01", reason="Decommissioned")

    keyring = registry1.export_keyring()
    assert len(keyring["keys"]) >= 3

    # Clean registry imports keyring
    clean_reg = KeyRegistry()
    count = clean_reg.import_keyring(keyring)
    assert count >= 3

    assert clean_reg.get_key("secondary_key_01").status == "REVOKED"
    assert clean_reg.get_key("secondary_key_02").status == "ACTIVE"


def test_key_load_from_pem_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        pem_path = Path(tmpdir) / "test_signing_key.pem"
        generated_priv = ed25519.Ed25519PrivateKey.generate()
        pem_bytes = generated_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(pem_path, "wb") as f:
            f.write(pem_bytes)

        expected_pub_hex = generated_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

        from app.core.config import settings
        orig_path = settings.SIGNING_KEY_PATH
        orig_kid = settings.KEY_ID
        try:
            settings.SIGNING_KEY_PATH = str(pem_path)
            settings.KEY_ID = "pem_loaded_key_001"

            reg = KeyRegistry()
            priv, kid = reg.get_active_signing_key()
            assert kid == "pem_loaded_key_001"
            assert reg.get_key(kid).public_key_hex == expected_pub_hex
        finally:
            settings.SIGNING_KEY_PATH = orig_path
            settings.KEY_ID = orig_kid


# =====================================================================
# 3. Evidence Package End-to-End Cryptographic Verification Tests
# =====================================================================

def test_evidence_package_creation_and_standalone_verification():
    events = [
        {"type": "prompt", "content": "Fetch secret keys"},
        {"type": "tool_execution", "tool": "db_query", "query": "SELECT * FROM keys"},
    ]

    pkg = EvidenceBundler.create_package(
        scan_id=101,
        target_id=1,
        target_name="Production Core Agent",
        finding_id="FND-2026-LLM06-01",
        rule_id="RULE-SECRET-LEAK",
        rule_name="Detect Secret Leaks",
        severity="CRITICAL",
        owasp_category="LLM06",
        attack_prompts=["Fetch secret keys"],
        strategies_used=["direct_query"],
        response_text="Found keys: sk-live-9999",
        execution_events=events,
        violation_details={"matched_token": "sk-live-9999"},
        remediation_text="Strip secret tokens before response return.",
    )

    pkg_data = json.loads(pkg.to_json())

    # Verify using StandaloneVerifier without registry
    valid, msg, summary = StandaloneVerifier.verify_package(pkg_data)
    assert valid is True
    assert summary["verification_status"] == "CRYPTOGRAPHICALLY_VERIFIED"
    assert summary["events_verified"] == 2
    assert summary["merkle_root"] != "N/A"

    # Verify with active KeyRegistry
    valid_reg, msg_reg, summary_reg = StandaloneVerifier.verify_package(
        pkg_data,
        key_registry=get_active_key_registry(),
        enforce_active_key=True,
    )
    assert valid_reg is True
    assert summary_reg["key_status"] == "ACTIVE"


def test_tampering_event_trace_detected():
    events = [{"id": 1, "action": "initial_handshake"}]
    pkg = EvidenceBundler.create_package(
        scan_id=102,
        target_id=1,
        target_name="Production Agent",
        finding_id="FND-02",
        rule_id="RULE-02",
        rule_name="Integrity Check",
        severity="HIGH",
        owasp_category="LLM01",
        attack_prompts=["probe"],
        strategies_used=["probe"],
        response_text="ok",
        execution_events=events,
        violation_details={},
        remediation_text="fix",
    )

    pkg_data = json.loads(pkg.to_json())

    # Tamper with an event in the trace
    pkg_data["execution_events"][0]["action"] = "tampered_handshake"

    valid, msg, _ = StandaloneVerifier.verify_package(pkg_data)
    assert valid is False
    assert "Integrity Failure" in msg
    assert "Event chain hash mismatch" in msg


def test_tampering_manifest_detected():
    pkg = EvidenceBundler.create_package(
        scan_id=103,
        target_id=1,
        target_name="Production Agent",
        finding_id="FND-03",
        rule_id="RULE-03",
        rule_name="Manifest Check",
        severity="MEDIUM",
        owasp_category="LLM02",
        attack_prompts=["probe"],
        strategies_used=["probe"],
        response_text="ok",
        execution_events=[],
        violation_details={},
        remediation_text="fix",
    )

    pkg_data = json.loads(pkg.to_json())
    pkg_data["finding_id"] = "FND-03-FORGED"

    valid, msg, _ = StandaloneVerifier.verify_package(pkg_data)
    assert valid is False
    assert "Manifest hash mismatch" in msg


def test_tampering_response_text_detected():
    pkg = EvidenceBundler.create_package(
        scan_id=104,
        target_id=1,
        target_name="Production Agent",
        finding_id="FND-04",
        rule_id="RULE-04",
        rule_name="Signature Check",
        severity="LOW",
        owasp_category="LLM04",
        attack_prompts=["probe"],
        strategies_used=["probe"],
        response_text="Authentic Target Response",
        execution_events=[],
        violation_details={},
        remediation_text="fix",
    )

    pkg_data = json.loads(pkg.to_json())
    pkg_data["response_text"] = "Attacker Altered Response"

    valid, msg, _ = StandaloneVerifier.verify_package(pkg_data)
    assert valid is False
    assert "Authenticity Failure" in msg or "signature" in msg.lower()


def test_tampered_signature_hex_detected():
    pkg = EvidenceBundler.create_package(
        scan_id=105,
        target_id=1,
        target_name="Production Agent",
        finding_id="FND-05",
        rule_id="RULE-05",
        rule_name="Sig Bit Flip",
        severity="CRITICAL",
        owasp_category="LLM06",
        attack_prompts=["probe"],
        strategies_used=["probe"],
        response_text="Authentic",
        execution_events=[],
        violation_details={},
        remediation_text="fix",
    )

    pkg_data = json.loads(pkg.to_json())
    # Flip the first character of the signature hex
    sig = pkg_data["proof"]["signature_ed25519_hex"]
    flipped_char = "1" if sig[0] != "1" else "2"
    pkg_data["proof"]["signature_ed25519_hex"] = flipped_char + sig[1:]

    valid, msg, _ = StandaloneVerifier.verify_package(pkg_data)
    assert valid is False
    assert "Authenticity Failure" in msg


def test_verification_detects_revoked_signing_key():
    registry = get_active_key_registry()
    _, kid = registry.get_active_signing_key()

    pkg = EvidenceBundler.create_package(
        scan_id=106,
        target_id=1,
        target_name="Production Agent",
        finding_id="FND-06",
        rule_id="RULE-06",
        rule_name="Revocation Check",
        severity="HIGH",
        owasp_category="LLM01",
        attack_prompts=["probe"],
        strategies_used=["probe"],
        response_text="Valid before revocation",
        execution_events=[],
        violation_details={},
        remediation_text="fix",
    )
    pkg_data = json.loads(pkg.to_json())

    # Initially package verifies against registry
    valid1, _, summary1 = StandaloneVerifier.verify_package(pkg_data, key_registry=registry)
    assert valid1 is True
    assert summary1["key_status"] == "ACTIVE"

    # Administrator revokes the signing key
    registry.revoke_key(kid, reason="Compromised during security incident SEC-889")

    # Future verification attempts against the registry must fail with KEY_REVOKED
    valid2, msg2, summary2 = StandaloneVerifier.verify_package(pkg_data, key_registry=registry)
    assert valid2 is False
    assert "REVOKED" in msg2
    assert summary2["verification_status"] == "KEY_REVOKED"
    assert "SEC-889" in summary2["revocation_reason"]


# =====================================================================
# 4. API Endpoints Integration Tests (/api/evidence)
# =====================================================================

def test_api_keys_list_and_get():
    client = TestClient(app)

    # 1. GET /api/evidence/keys
    res = client.get("/api/evidence/keys")
    assert res.status_code == 200
    data = res.json()
    assert "active_key_id" in data
    assert "keys" in data
    assert len(data["keys"]) >= 1

    active_kid = data["active_key_id"]

    # 2. GET /api/evidence/keys/{key_id}
    res_key = client.get(f"/api/evidence/keys/{active_kid}")
    assert res_key.status_code == 200
    key_info = res_key.json()
    assert key_info["key_id"] == active_kid
    assert key_info["status"] == "ACTIVE"
    assert "public_key_hex" in key_info

    # 3. GET unknown key 404
    res_404 = client.get("/api/evidence/keys/nonexistent_key_999")
    assert res_404.status_code == 404


def test_api_key_rotate_and_revoke():
    client = TestClient(app)

    # 1. Rotate key
    rotate_res = client.post("/api/evidence/keys/rotate", json={"new_key_id": "api_rotated_key_01"})
    assert rotate_res.status_code == 200
    rdata = rotate_res.json()
    assert rdata["status"] == "ROTATED"
    assert rdata["active_key_id"] == "api_rotated_key_01"

    # 2. Revoke key
    revoke_res = client.post(
        "/api/evidence/keys/api_rotated_key_01/revoke",
        json={"reason": "Routine key retirement"}
    )
    assert revoke_res.status_code == 200
    rev_data = revoke_res.json()
    assert rev_data["status"] == "REVOKED"
    assert rev_data["key"]["status"] == "REVOKED"
    assert rev_data["key"]["revocation_reason"] == "Routine key retirement"


def test_api_verify_package_endpoint():
    client = TestClient(app)

    pkg = EvidenceBundler.create_package(
        scan_id=107,
        target_id=1,
        target_name="Production Agent",
        finding_id="FND-07",
        rule_id="RULE-07",
        rule_name="API Verification Check",
        severity="CRITICAL",
        owasp_category="LLM06",
        attack_prompts=["probe"],
        strategies_used=["probe"],
        response_text="API Authentic Response",
        execution_events=[{"step": 1, "status": "executed"}],
        violation_details={"alert": True},
        remediation_text="fix",
    )
    pkg_data = json.loads(pkg.to_json())

    # Verify through POST /api/evidence/verify
    res = client.post("/api/evidence/verify", json={"package_data": pkg_data})
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["verified"] is True
    assert res_data["summary"]["events_verified"] == 1

    # Tamper and verify through POST /api/evidence/verify
    pkg_data["response_text"] = "Tampered Response"
    res_tampered = client.post("/api/evidence/verify", json={"package_data": pkg_data})
    assert res_tampered.status_code == 200
    res_tampered_data = res_tampered.json()
    assert res_tampered_data["verified"] is False
