"""API Router for Policy-as-Code Framework."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from app.policy_engine import (
    PolicyCompiler,
    PolicyEvaluator,
    BUILTIN_TEMPLATES,
    PolicyCompilerError,
)

router = APIRouter(prefix="/policy-engine", tags=["Policy-as-Code"])


class CompileRequest(BaseModel):
    yaml_content: str


class EvaluateRequest(BaseModel):
    yaml_content: str
    response_text: str
    execution_events: List[Dict[str, Any]] = []
    session_user_id: str = "usr_authenticated_tenant"
    target_mode: str = "INSTRUMENTED"


@router.get("/templates")
def get_templates():
    """Returns built-in enterprise policy templates."""
    return BUILTIN_TEMPLATES


@router.post("/compile")
def compile_policy(request: CompileRequest):
    """Compiles and validates a declarative YAML policy."""
    try:
        compiled = PolicyCompiler.compile_yaml(request.yaml_content)
        return {
            "valid": True,
            "name": compiled.name,
            "version": compiled.version,
            "description": compiled.description,
            "rules_count": len(compiled.rules),
            "rules": [r.model_dump() for r in compiled.rules],
        }
    except PolicyCompilerError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/evaluate")
def evaluate_trace(request: EvaluateRequest):
    """Evaluates an execution trace against a compiled policy."""
    try:
        compiled = PolicyCompiler.compile_yaml(request.yaml_content)
        results = PolicyEvaluator.evaluate_policy(
            policy=compiled,
            response_text=request.response_text,
            execution_events=request.execution_events,
            session_user_id=request.session_user_id,
            target_mode=request.target_mode,
        )
        return {
            "policy_name": compiled.name,
            "rules_evaluated": len(results),
            "violations_found": sum(1 for r in results if r.violated),
            "results": [r.to_dict() for r in results],
        }
    except PolicyCompilerError as e:
        raise HTTPException(status_code=400, detail=str(e))
