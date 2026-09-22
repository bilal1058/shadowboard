from fastapi import APIRouter
from app.api.endpoints import (
    targets,
    policies,
    scans,
    findings,
    policy_as_code,
    planner,
    regression,
    bench,
    evidence,
    integrations,
)

api_router = APIRouter(prefix="/api")

@api_router.get("/health", tags=["Health"])
async def api_health():
    return {"status": "ok", "service": "shadowboard"}


# Core endpoints
api_router.include_router(targets.router)
api_router.include_router(policies.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)

# Enterprise AI Assurance platform endpoints
api_router.include_router(policy_as_code.router)
api_router.include_router(planner.router)
api_router.include_router(regression.router)
api_router.include_router(bench.router)
api_router.include_router(evidence.router)
api_router.include_router(integrations.router)
