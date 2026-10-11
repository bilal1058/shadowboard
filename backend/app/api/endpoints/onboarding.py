"""Target Onboarding Wizard & Browser Discovery Endpoints."""

from __future__ import annotations

import logging
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.browser.adapter import BrowserChatbotAdapter
from app.browser.models import DiscoveredChatWidget, OnboardingRequest, TargetScope
from app.browser.scope import ScopeViolationError
from app.core.ssrf import SSRFValidationError, validate_target_url

logger = logging.getLogger("shadowboard.onboarding")

router = APIRouter(prefix="/onboarding", tags=["Target Onboarding"])


class ConfirmTargetProfileRequest(BaseModel):
    """Payload to confirm or adjust discovered target profile."""

    target_url: str
    target_name: str
    target_mode: str = "INSTRUMENTED"
    operator_authorized: bool
    authorized_by: str
    launcher_selector: str = ""
    input_selector: str = ""
    send_button_selector: str = ""
    scope_allowed_domains: List[str] = []
    max_request_rate_per_sec: float = 2.0
    max_test_duration_sec: int = 300
    planned_probes: List[Dict[str, Any]] = []


@router.post("/discover", response_model=DiscoveredChatWidget)
async def discover_target(request: OnboardingRequest) -> DiscoveredChatWidget:
    """Discover chatbot widgets, accessibility roles, and dynamic interfaces on an authorized website."""
    if not request.operator_authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization Refusal: You must confirm ownership or explicit authorization to assess this target.",
        )

    if not request.authorized_by.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization Refusal: Operator name/email must be provided in 'authorized_by'.",
        )

    # 1. Validate Target URL with SSRF Protection
    try:
        validated_url = validate_target_url(request.target_url, allow_local=False)
    except SSRFValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security Scope Violation: {exc}",
        )

    # 2. Build Target Scope
    scope = TargetScope(
        target_url=validated_url,
        allowed_domains=request.allowed_domains or [],
        operator_authorized=True,
        authorized_by=request.authorized_by,
        disallow_state_changing_actions=True,
    )

    if request.dry_run_only:
        return DiscoveredChatWidget(
            target_url=validated_url,
            found=True,
            confidence=0.5,
            discovery_method="dry_run_preview",
            planned_probes=[
                {
                    "probe_id": "DRY-01",
                    "name": "Dry Run Baseline",
                    "category": "BENIGN",
                    "description": "Simulated connection check.",
                }
            ],
        )

    # 3. Execute Browser Automation Discovery
    adapter = BrowserChatbotAdapter(scope=scope)
    try:
        discovered = await adapter.discover_chat_interface(
            custom_launcher_selector=request.custom_launcher_selector,
            custom_input_selector=request.custom_input_selector,
            custom_send_button_selector=request.custom_send_button_selector,
            send_baseline_message=True,
        )
        return discovered
    except ScopeViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scope boundary violated: {exc}",
        )
    except Exception as exc:
        logger.exception("Target discovery failure")
        return DiscoveredChatWidget(
            target_url=validated_url,
            found=False,
            error_message=f"Browser discovery failed: {exc}",
        )


import json
import aiosqlite
from fastapi import Depends
from app.db.session import get_db


@router.post("/confirm")
async def confirm_target_profile(
    request: ConfirmTargetProfileRequest,
    db: aiosqlite.Connection = Depends(get_db),
) -> Dict[str, Any]:
    """Saves a confirmed target profile with verified selectors, planned test suite, and scope into DB."""
    if not request.operator_authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operator authorization must be confirmed before saving profile.",
        )

    capabilities = {
        "selectors": {
            "launcher": request.launcher_selector,
            "input": request.input_selector,
            "send_button": request.send_button_selector,
        },
        "scope": {
            "allowed_domains": request.scope_allowed_domains,
            "max_rate": request.max_request_rate_per_sec,
            "max_duration_sec": request.max_test_duration_sec,
            "authorized_by": request.authorized_by,
        },
        "planned_probes_count": len(request.planned_probes),
    }

    target_id = None
    try:
        existing_cur = await db.execute(
            "SELECT id FROM targets WHERE name = ? AND base_url = ?",
            (request.target_name, request.target_url),
        )
        existing_row = await existing_cur.fetchone()
        if existing_row:
            target_id = existing_row[0]
            await db.execute(
                """
                UPDATE targets
                SET name = ?, base_url = ?, model_name = ?, target_type = ?, target_mode = ?, capabilities_json = ?
                WHERE id = ?
                """,
                (
                    request.target_name,
                    request.target_url,
                    "custom-chatbot",
                    "CUSTOM_BROWSER_CHATBOT" if request.target_mode == "BLACK_BOX" else "EXTERNAL_SUPPORT",
                    request.target_mode,
                    json.dumps(capabilities),
                    target_id,
                ),
            )
        else:
            cursor = await db.execute(
                """
                INSERT INTO targets (name, base_url, model_name, target_type, target_mode, capabilities_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    request.target_name,
                    request.target_url,
                    "custom-chatbot",
                    "CUSTOM_BROWSER_CHATBOT" if request.target_mode == "BLACK_BOX" else "EXTERNAL_SUPPORT",
                    request.target_mode,
                    json.dumps(capabilities),
                ),
            )
            target_id = cursor.lastrowid
        await db.commit()
    except Exception as exc:
        logger.warning(f"Could not persist confirmed target to database: {exc}")

    profile = {
        "target_id": target_id,
        "target_url": request.target_url,
        "target_name": request.target_name,
        "target_mode": request.target_mode,
        "authorized_by": request.authorized_by,
        "selectors": {
            "launcher": request.launcher_selector,
            "input": request.input_selector,
            "send_button": request.send_button_selector,
        },
        "scope": {
            "allowed_domains": request.scope_allowed_domains,
            "max_rate": request.max_request_rate_per_sec,
            "max_duration_sec": request.max_test_duration_sec,
        },
        "planned_probes_count": len(request.planned_probes),
        "status": "READY_FOR_ASSESSMENT",
    }
    return {
        "status": "CONFIRMED",
        "target_id": target_id,
        "target_name": request.target_name,
        "message": "Target profile saved and configured for authorized assessment.",
        "target_profile": profile,
    }


@router.get("/templates")
async def list_onboarding_templates() -> Dict[str, Any]:
    """Lists standard generic attack families and testing modes supported by ShadowBoard."""
    return {
        "testing_modes": [
            {
                "mode": "BLACK_BOX",
                "name": "Public Black-Box Assessment",
                "description": "Tests observable responses through public chat UI without knowledge of internal tools or database schema.",
            },
            {
                "mode": "AUTHENTICATED_BLACK_BOX",
                "name": "Authenticated Black-Box Assessment",
                "description": "Tests observable responses using operator-provided authorized credentials and test account roles.",
            },
            {
                "mode": "INSTRUMENTED",
                "name": "Instrumented White-Box / Gray-Box Assessment",
                "description": "Tests deep tool execution traces, database invariants, and telemetry via agent adapter or observation sidecar.",
            },
        ],
        "generic_attack_families": [
            "BOLA / Cross-Tenant Resource Disclosure",
            "System Instruction / Prompt Directive Extraction",
            "Excessive Agency & Unauthorized Side Effects",
            "Confused Deputy & Tool Argument Manipulation",
            "RAG Confidential Document Disclosure",
            "Conversational Memory Poisoning & Role Escalation",
        ],
    }
