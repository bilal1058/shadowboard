from fastapi import APIRouter, Depends, HTTPException
import json
import aiosqlite
from typing import Optional
from pydantic import BaseModel, HttpUrl
from app.db.session import get_db
from app.schemas.target import TargetContract, TargetResponse
from app.core.ssrf import validate_target_url, safe_http_get_json, SSRFValidationError

router = APIRouter(prefix="/targets", tags=["Targets"])

DEFAULT_TARGET = {
    "name": "Meridian Support AI (Reference Target)",
    "base_url": "http://127.0.0.1:8000/target-app",
    "model_name": "qwen-flash",
    "target_type": "EXTERNAL_SUPPORT",
    "target_mode": "INSTRUMENTED",
    "capabilities": {
        "chat": True,
        "rag": False,
        "tools": False,
        "data_access": False,
        "tool_names": []
    }
}

class ConnectionCheckRequest(BaseModel):
    base_url: str
    allow_local: bool = False

@router.post("/test-connection")
async def test_connection(request: ConnectionCheckRequest):
    """Validate a target by reading its real health and contract endpoints with SSRF protections."""
    is_local_ref = "127.0.0.1:8000" in request.base_url or "localhost:8000" in request.base_url
    effective_allow_local = request.allow_local or is_local_ref
    try:
        validated_base = validate_target_url(request.base_url, allow_local=effective_allow_local)
    except SSRFValidationError as exc:
        raise HTTPException(status_code=400, detail=f"SSRF validation blocked target URL: {exc}")

    try:
        health_data = await safe_http_get_json(f"{validated_base}/health", allow_local=effective_allow_local)
        contract_data = await safe_http_get_json(f"{validated_base}/contract", allow_local=effective_allow_local)
    except SSRFValidationError as exc:
        raise HTTPException(status_code=422, detail=f"Target connection or validation failed: {exc}")

    return {"connected": True, "health": health_data, "contract": contract_data}

@router.post("", response_model=TargetResponse)
async def create_target(target: TargetContract, db: aiosqlite.Connection = Depends(get_db)):
    # Local reference targets built into ShadowBoard are allowed loopback
    is_local_ref = "127.0.0.1:8000" in target.base_url or "localhost:8000" in target.base_url
    try:
        validated_base = validate_target_url(target.base_url, allow_local=is_local_ref)
    except SSRFValidationError as exc:
        raise HTTPException(status_code=400, detail=f"SSRF validation blocked target URL: {exc}")

    cursor = await db.execute(
        "INSERT INTO targets (name, base_url, model_name, target_type, target_mode, capabilities_json) VALUES (?, ?, ?, ?, ?, ?)",
        (target.name, validated_base, target.model_name, target.target_type, target.target_mode, json.dumps(target.capabilities.model_dump()))
    )
    await db.commit()
    target_id = cursor.lastrowid
    return TargetResponse(
        id=target_id,
        name=target.name,
        base_url=validated_base,
        model_name=target.model_name,
        target_type=target.target_type,
        target_mode=target.target_mode,
        capabilities=target.capabilities
    )

@router.get("", response_model=list[TargetResponse])
async def list_targets(db: aiosqlite.Connection = Depends(get_db)):
    cursor = await db.execute("SELECT id, name, base_url, model_name, target_type, target_mode, capabilities_json FROM targets ORDER BY id DESC")
    rows = await cursor.fetchall()
    results = []
    for r in rows:
        results.append(TargetResponse(
            id=r[0],
            name=r[1],
            base_url=r[2],
            model_name=r[3],
            target_type=r[4],
            target_mode=r[5],
            capabilities=json.loads(r[6])
        ))
    return results


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: int, db: aiosqlite.Connection = Depends(get_db)):
    cursor = await db.execute("SELECT id, name, base_url, model_name, target_type, target_mode, capabilities_json FROM targets WHERE id = ?", (target_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")
    return TargetResponse(
        id=row[0],
        name=row[1],
        base_url=row[2],
        model_name=row[3],
        target_type=row[4],
        target_mode=row[5],
        capabilities=json.loads(row[6])
    )


@router.get("/{target_id}/documents")
async def get_target_documents(target_id: int, db: aiosqlite.Connection = Depends(get_db)):
    cursor = await db.execute("SELECT id, name, base_url, target_type, capabilities_json FROM targets WHERE id = ?", (target_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")
    
    base_url = row[2]
    target_type = row[3]
    
    if target_type == "INTERNAL_RAG" or "internal-rag" in base_url:
        from app.internal_rag.rag_store import internal_vector_store
        catalog = internal_vector_store.get_catalog()
        return {
            "target_id": target_id,
            "target_name": row[1],
            "has_rag": True,
            "document_count": len(catalog),
            "documents": catalog
        }
    
    return {
        "target_id": target_id,
        "target_name": row[1],
        "has_rag": False,
        "document_count": 0,
        "documents": []
    }
