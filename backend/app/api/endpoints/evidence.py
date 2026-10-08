"""API Router for Verifiable Evidence System."""

from fastapi import APIRouter, HTTPException, Depends, Response
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import aiosqlite
import json

from app.db.session import get_db
from app.evidence import EvidenceBundler, StandaloneVerifier, get_active_key_registry

router = APIRouter(prefix="/evidence", tags=["Verifiable Evidence"])


class VerifyEvidenceRequest(BaseModel):
    package_data: Dict[str, Any]
    mode: str = "TRUSTED_SIGNER"  # TRUSTED_SIGNER | HISTORICAL_SIGNER | CRYPTOGRAPHIC_ONLY
    enforce_active_key: bool = True


class RevokeKeyRequest(BaseModel):
    reason: str = "Key rotated or retired"


class RotateKeyRequest(BaseModel):
    new_key_id: Optional[str] = None


@router.get("/keys")
def list_public_keys():
    """Lists all registered Ed25519 public signing keys and their statuses (never exposes private keys)."""
    registry = get_active_key_registry()
    keyring = registry.export_keyring()
    return {
        "active_key_id": keyring["active_key_id"],
        "keys": keyring["keys"],
    }


@router.get("/keys/{key_id}")
def get_public_key(key_id: str):
    """Retrieves metadata and public key for a specific registered signing key."""
    registry = get_active_key_registry()
    record = registry.get_key(key_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Key ID '{key_id}' not found in registry")
    return record.model_dump()


@router.post("/keys/rotate")
def rotate_signing_key(request: RotateKeyRequest = None):
    """Rotates to a newly generated private signing key, keeping old key registered for historical verification."""
    registry = get_active_key_registry()
    req_kid = request.new_key_id if request else None
    _, new_record = registry.rotate_key(new_key_id=req_kid)
    return {
        "status": "ROTATED",
        "new_key": new_record.model_dump(),
        "active_key_id": new_record.key_id,
    }


@router.post("/keys/{key_id}/revoke")
def revoke_signing_key(key_id: str, request: RevokeKeyRequest = RevokeKeyRequest()):
    """Revokes a signing key, causing future verification of packages signed with this key to fail."""
    registry = get_active_key_registry()
    try:
        record = registry.revoke_key(key_id=key_id, reason=request.reason)
        return {
            "status": "REVOKED",
            "key": record.model_dump(),
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Key ID '{key_id}' not found in registry")


def _lookup_policy_rule_name(rule_id: str, fallback_objective: Optional[str] = None) -> str:
    """Resolves authentic immutable policy rule name from registered security policies."""
    from app.api.endpoints.policies import SUPPORT_POLICY, INTERNAL_RAG_POLICY
    for p in SUPPORT_POLICY.get("policies", []) + INTERNAL_RAG_POLICY.get("policies", []):
        if p.get("id") == rule_id:
            return p.get("name", rule_id)
    if fallback_objective and fallback_objective.strip():
        return fallback_objective.strip()
    return f"Policy Assertion: {rule_id}"


@router.get("/{finding_id}/package")
async def get_evidence_package(finding_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Generates and returns an independently verifiable cryptographic evidence package for a finding."""
    cursor = await db.execute(
        """
        SELECT f.scan_id, f.finding_id, f.owasp_category, f.status, f.severity, f.remediation, f.evidence_json, f.evidence_hash,
               s.target_id, t.name, t.target_mode, f.objective_id, ao.policy_rule_id, ao.objective
        FROM findings f
        JOIN scan_runs s ON f.scan_id = s.id
        JOIN targets t ON s.target_id = t.id
        LEFT JOIN attack_objectives ao ON f.objective_id = ao.id
        WHERE f.finding_id = ?
        """,
        (finding_id,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    scan_id = row[0]
    finding_id = row[1]
    owasp_cat = row[2]
    status = row[3]
    severity = row[4]
    remediation = row[5]
    evidence_json = json.loads(row[6]) if isinstance(row[6], str) else (row[6] or {})
    target_id = row[8]
    target_name = row[9]
    target_mode = row[10]
    objective_id = row[11] if len(row) > 11 else None
    rule_id = row[12] if len(row) > 12 and row[12] else finding_id
    ao_objective = row[13] if len(row) > 13 else None
    actual_rule_name = _lookup_policy_rule_name(rule_id, ao_objective)

    # Fetch attempts strictly matching the finding's objective provenance
    if objective_id:
        att_cursor = await db.execute(
            """
            SELECT id, prompt_text, response_text, strategy, turn_number
            FROM attack_attempts
            WHERE objective_id = ?
            ORDER BY turn_number ASC, id ASC
            """,
            (objective_id,)
        )
    else:
        att_cursor = await db.execute(
            """
            SELECT id, prompt_text, response_text, strategy, turn_number
            FROM attack_attempts
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,)
        )
    att_rows = await att_cursor.fetchall()
    attempt_ids = [r[0] for r in att_rows]
    prompts = [r[1] for r in att_rows] if att_rows else ["Audited attack sequence probe."]
    strategies = [r[3] for r in att_rows] if att_rows else ["adaptive_fsm"]
    last_response = att_rows[-1][2] if att_rows else "Audited target output."

    # Fetch execution events strictly linked to this objective's attempts
    events = []
    if attempt_ids:
        placeholders = ",".join("?" for _ in attempt_ids)
        ev_cursor = await db.execute(
            f"""
            SELECT event_type, event_data, source
            FROM execution_events
            WHERE attempt_id IN ({placeholders})
            ORDER BY id ASC
            """,
            tuple(attempt_ids)
        )
        ev_rows = await ev_cursor.fetchall()
        for er in ev_rows:
            try:
                ev_data = json.loads(er[1]) if isinstance(er[1], str) else (er[1] or {})
            except Exception:
                ev_data = {}
            events.append({"event_type": er[0], "event_data": ev_data, "source": er[2] if len(er) > 2 else "target"})

    pkg = EvidenceBundler.create_package(
        scan_id=scan_id,
        target_id=target_id,
        target_name=target_name,
        finding_id=finding_id,
        rule_id=rule_id,
        rule_name=actual_rule_name,
        severity=severity,
        owasp_category=owasp_cat,
        attack_prompts=prompts,
        strategies_used=strategies,
        response_text=last_response,
        execution_events=events,
        violation_details=evidence_json,
        remediation_text=remediation,
        target_mode=target_mode,
    )

    return pkg.model_dump()


@router.post("/verify")
def verify_offline_package(request: VerifyEvidenceRequest):
    """Verifies the cryptographic integrity and authenticity of an evidence package against the KeyRegistry."""
    registry = get_active_key_registry()
    valid, message, summary = StandaloneVerifier.verify_package(
        request.package_data,
        key_registry=registry,
        enforce_active_key=request.enforce_active_key,
        mode=request.mode,
    )
    return {
        "verified": valid,
        "message": message,
        "summary": summary,
    }

