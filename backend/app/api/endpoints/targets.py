from fastapi import APIRouter, Depends, HTTPException
import json
import aiosqlite
from app.db.session import get_db
from app.schemas.target import TargetResponse

router = APIRouter(prefix="/targets", tags=["Targets"])

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
