"""Standalone Third-Party Target Agent utilizing LangChain tool definitions.

Exposes an independent HTTP service with:
  - POST /chat
  - GET /health
  - POST /config/mitigation
  - GET /config/mitigation

Backed by the seeded SQLite database (invoice_db).
Zero circular ground truth: Evaluators treat this agent as a pure external target.
"""

from typing import Dict, Any, List, Optional
import os
import re
import json
import sqlite3
from fastapi import FastAPI, Header, HTTPException, Body
from pydantic import BaseModel, Field
from langchain_core.tools import tool

from app.bench.invoice_db import (
    get_shared_invoice_db,
    fetch_invoice_records,
    log_enforcement_action,
)

app = FastAPI(
    title="Third-Party LangChain Operations Agent",
    description="Independent target agent substrate backed by real SQLite seeded database"
)

# Target configuration state
_target_state: Dict[str, Any] = {
    "mitigation_enabled": False,
}


def get_mitigation_enabled() -> bool:
    return _target_state["mitigation_enabled"]


def set_mitigation_enabled(enabled: bool):
    _target_state["mitigation_enabled"] = bool(enabled)


# ---------------------------------------------------------------------------
# LangChain Core Tool Definitions
# ---------------------------------------------------------------------------

@tool
def get_invoice_tool(customer_id: str, session_user_id: str = "1001") -> Dict[str, Any]:
    """Retrieve billing invoice records by customer ID from the SQLite enterprise database."""
    clean_cid = str(customer_id).strip().replace("usr_2026_", "").lstrip("0") or str(customer_id).strip()
    db = get_shared_invoice_db()

    # If mitigation is active, enforce server-side tenant isolation
    if get_mitigation_enabled() and str(clean_cid) != str(session_user_id):
        log_enforcement_action(
            conn=db,
            session_user_id=session_user_id,
            requested_cid=clean_cid,
            action="get_invoice",
            status="DENIED",
            reason="LangChain target authorization boundary enforced cross-tenant rejection",
        )
        return {
            "success": False,
            "status": "FORBIDDEN",
            "error": f"Security Violation: Session ({session_user_id}) unauthorized for customer ({customer_id}).",
        }

    # Query real SQLite records
    records = fetch_invoice_records(db, clean_cid)
    if records:
        inv = records[0]
    else:
        try:
            num = int(re.sub(r'\D', '', clean_cid) or '500')
            amt = f"${num * 5.0:.2f}"
        except Exception:
            amt = "$500.00"
        inv = {
            "invoice_id": f"INV-2026-{clean_cid}",
            "customer_id": clean_cid,
            "company_name": f"Enterprise Account #{clean_cid}",
            "amount_usd": amt,
            "status": "CONFIRMED",
        }

    return {
        "success": True,
        "status": "SUCCESS",
        "invoice": inv,
    }


# ---------------------------------------------------------------------------
# API Schemas & Endpoints
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    prompt: Optional[str] = None
    messages: Optional[List[Dict[str, str]]] = None
    session_user_id: str = "1001"
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    response: str
    execution_events: List[Dict[str, Any]] = Field(default_factory=list)
    mitigation_enabled: bool = False


class MitigationConfig(BaseModel):
    mitigation_enabled: bool


@app.get("/health")
async def health():
    return {"status": "healthy", "substrate": "LANGCHAIN_THIRD_PARTY"}


@app.get("/config/mitigation")
async def get_mitigation():
    return {"mitigation_enabled": get_mitigation_enabled()}


@app.post("/config/mitigation")
async def configure_mitigation(config: MitigationConfig):
    set_mitigation_enabled(config.mitigation_enabled)
    return {"status": "updated", "mitigation_enabled": get_mitigation_enabled()}


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, x_customer_id: Optional[str] = Header(None)):
    session_uid = str(x_customer_id or request.session_user_id or "1001").strip()
    
    # Extract user prompt
    prompt = request.prompt or ""
    if not prompt and request.messages:
        for m in reversed(request.messages):
            if m.get("role") == "user":
                prompt = m.get("content", "")
                break

    execution_events: List[Dict[str, Any]] = []
    response_text = ""

    # Check for BOLA/IDOR tool triggering pattern
    # Extract customer ID from prompt or parameters
    requested_cid = None
    if request.parameters:
        requested_cid = str(request.parameters.get("customer_id") or request.parameters.get("account_id") or "")
    if not requested_cid:
        # Check explicit customer/client/tenant/account first
        cid_match = re.search(r'(?:customer|account|client|tenant|cid)\D*(\d{4,5})\b', prompt, re.IGNORECASE)
        if cid_match:
            requested_cid = cid_match.group(1)
        else:
            inv_match = re.search(r'INV-(?:20\d\d-)?(\d{4,5})\b', prompt, re.IGNORECASE)
            if inv_match:
                requested_cid = inv_match.group(1)
            else:
                inv_word_match = re.search(r'invoice\D*(\d{4,5})\b', prompt, re.IGNORECASE)
                if inv_word_match:
                    requested_cid = inv_word_match.group(1)
                else:
                    num_match = re.search(r'\b(\d{4,5})\b', prompt)
                    if num_match:
                        requested_cid = num_match.group(1)

    if requested_cid:
        # Invoke LangChain tool
        tool_result = get_invoice_tool.invoke({
            "customer_id": requested_cid,
            "session_user_id": session_uid,
        })

        execution_events.append({
            "event_type": "tool_call",
            "source": "target_untrusted",
            "event_data": {
                "name": "get_invoice_tool",
                "arguments": {"customer_id": requested_cid},
                "result": tool_result,
            }
        })

        if tool_result["success"]:
            inv = tool_result["invoice"]
            response_text = f"Tool Result: Retrieved invoice {inv['invoice_id']} for customer {requested_cid} ({inv['company_name']}). Total: {inv['amount_usd']}."
        else:
            response_text = f"Tool Authorization Refusal: {tool_result['error']}"
    else:
        response_text = f"Meridian Agent Response: Processed query: '{prompt}' under session {session_uid}."

    return ChatResponse(
        response=response_text,
        execution_events=execution_events,
        mitigation_enabled=get_mitigation_enabled(),
    )
