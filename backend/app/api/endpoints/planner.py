"""API Router for Autonomous Attack Planner."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import aiosqlite
import json

from app.db.session import get_db
from app.planner import SchemaAnalyzer, AutonomousAttackPlanner, AutonomousAttackPlan

router = APIRouter(prefix="/planner", tags=["Autonomous Attack Planner"])


class GeneratePlanRequest(BaseModel):
    target_id: int
    objective_vector: Optional[str] = None
    target_tenant: str = "tenant_target_02"
    session_user_id: str = "user_session_01"


class ExecutePlanRequest(BaseModel):
    plan: AutonomousAttackPlan


@router.post("/surface")
async def inspect_target_surface(target_id: int, db: aiosqlite.Connection = Depends(get_db)):
    """Inspects target capabilities and tools to determine vulnerable vectors."""
    cursor = await db.execute("SELECT id, name, target_type, target_mode, capabilities_json FROM targets WHERE id = ?", (target_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")

    capabilities = json.loads(row[4])
    surface = SchemaAnalyzer.analyze_target(
        target_id=row[0],
        target_name=row[1],
        target_type=row[2],
        target_mode=row[3],
        capabilities=capabilities,
    )
    return surface.model_dump()


@router.post("/generate")
async def generate_attack_plan(request: GeneratePlanRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Generates a multi-stage autonomous attack plan tailored to target architecture."""
    cursor = await db.execute("SELECT id, name, target_type, target_mode, capabilities_json FROM targets WHERE id = ?", (request.target_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")

    capabilities = json.loads(row[4])
    surface = SchemaAnalyzer.analyze_target(
        target_id=row[0],
        target_name=row[1],
        target_type=row[2],
        target_mode=row[3],
        capabilities=capabilities,
    )

    plan = AutonomousAttackPlanner.generate_plan(
        surface=surface,
        objective_vector=request.objective_vector,
        target_tenant=request.target_tenant,
        session_user_id=request.session_user_id,
    )
    return plan.model_dump()


@router.post("/execute")
async def execute_attack_plan(request: ExecutePlanRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Executes the autonomous attack plan against the live target."""
    cursor = await db.execute("SELECT base_url, target_mode FROM targets WHERE id = ?", (request.plan.target_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")

    base_url = row[0]
    target_mode = row[1]

    executed_plan = await AutonomousAttackPlanner.execute_plan(
        plan=request.plan,
        base_url=base_url,
        target_mode=target_mode,
    )
    return executed_plan.model_dump()
