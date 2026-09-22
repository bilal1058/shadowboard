from fastapi import APIRouter, Depends, HTTPException
import json
import hashlib
import aiosqlite
from typing import List, Dict, Any
from app.db.session import get_db
from app.core.replay import regression_engine

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("")
@router.get("/")
async def list_all_findings(limit: int = 50, db: aiosqlite.Connection = Depends(get_db)):
    cursor = await db.execute(
        "SELECT id, finding_id, owasp_category, taxonomy_version, "
        "application_security_class, status, attack_outcome, evidence_status, "
        "confidence, severity, evidence_json, evidence_hash, remediation, scan_id "
        "FROM findings ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = await cursor.fetchall()
    results = []
    for r in rows:
        try:
            ev = json.loads(r[10]) if r[10] else {}
        except Exception:
            ev = {}
        results.append({
            "id": r[0],
            "finding_id": r[1],
            "owasp_category": r[2],
            "taxonomy_version": r[3],
            "application_security_class": r[4],
            "status": r[5],
            "attack_outcome": r[6],
            "evidence_status": r[7],
            "evidence_strength": r[8],
            "confidence": r[8],  # Deprecated compatibility alias.
            "severity": r[9],
            "evidence": ev,
            "evidence_hash": r[11],
            "remediation": r[12],
            "scan_id": r[13],
        })
    return results


@router.get("/scan/{scan_id}")
async def list_scan_findings(scan_id: int, db: aiosqlite.Connection = Depends(get_db)):
    cursor = await db.execute(
        "SELECT id, finding_id, owasp_category, taxonomy_version, "
        "application_security_class, status, attack_outcome, evidence_status, "
        "confidence, severity, evidence_json, evidence_hash, remediation "
        "FROM findings WHERE scan_id = ?",
        (scan_id,),
    )
    rows = await cursor.fetchall()
    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "finding_id": r[1],
            "owasp_category": r[2],
            "taxonomy_version": r[3],
            "application_security_class": r[4],
            "status": r[5],
            "attack_outcome": r[6],
            "evidence_status": r[7],
            "evidence_strength": r[8],
            "confidence": r[8],  # Deprecated compatibility alias.
            "severity": r[9],
            "evidence": json.loads(r[10]),
            "evidence_hash": r[11],
            "remediation": r[12],
        })
    return results


@router.get("/{finding_id}/verify")
async def verify_finding_hash(finding_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Verify SHA-256 content hash of finding evidence.
    
    This proves: "The current evidence hashes to this value."
    It does NOT prove: "Nobody modified the record."
    """
    cursor = await db.execute(
        "SELECT evidence_json, evidence_hash FROM findings WHERE finding_id = ?",
        (finding_id,),
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    raw_json_str = row[0]
    stored_hash = row[1]

    parsed_json = json.loads(raw_json_str)
    canonical_json = json.dumps(parsed_json, sort_keys=True)
    computed_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    is_valid = computed_hash == stored_hash

    return {
        "finding_id": finding_id,
        "integrity_check": "SHA-256 content hash",
        "hash_valid": is_valid,
        "stored_hash": stored_hash,
        "computed_hash": computed_hash,
    }


@router.post("/{finding_id}/replay")
async def replay_finding(finding_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Replay the exact exploit sequence from a confirmed finding.
    
    Used for security regression testing: after a fix is deployed,
    replay the same attack to verify the vulnerability is closed.
    """
    cursor = await db.execute(
        "SELECT f.exploit_sequence_json, f.owasp_category, f.severity, f.remediation, "
        "o.policy_rule_id, o.family, "
        "t.base_url, t.capabilities_json, sr.scan_mode "
        "FROM findings f "
        "JOIN attack_objectives o ON f.objective_id = o.id "
        "JOIN scan_runs sr ON f.scan_id = sr.id "
        "JOIN targets t ON sr.target_id = t.id "
        "WHERE f.finding_id = ?",
        (finding_id,),
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    exploit_seq = row[0]
    if not exploit_seq:
        raise HTTPException(
            status_code=422,
            detail="No exploit sequence saved for this finding.",
        )

    base_url = row[6]
    capabilities = json.loads(row[7])
    scan_mode = row[8]

    # Fetch the policy rule definition
    policy_rule_id = row[4]
    pol_cursor = await db.execute(
        "SELECT policy_json FROM policies WHERE target_id = ("
        "  SELECT target_id FROM scan_runs WHERE id = ("
        "    SELECT scan_id FROM findings WHERE finding_id = ?"
        "  )"
        ") ORDER BY id DESC LIMIT 1",
        (finding_id,),
    )
    pol_row = await pol_cursor.fetchone()
    if not pol_row:
        raise HTTPException(status_code=422, detail="Policy not found for target.")

    policy_data = json.loads(pol_row[0])
    rule_dict = None
    for p in policy_data.get("policies", []):
        if p["id"] == policy_rule_id:
            rule_dict = p
            break

    if not rule_dict:
        raise HTTPException(
            status_code=422,
            detail=f"Policy rule {policy_rule_id} not found in current policy.",
        )

    result = await regression_engine.replay_exploit(
        exploit_sequence_json=exploit_seq,
        target_base_url=base_url,
        rule_dict=rule_dict,
        scan_mode=scan_mode,
        target_capabilities=capabilities,
    )

    return {
        "finding_id": finding_id,
        **result,
    }
