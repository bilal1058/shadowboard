"""Configurable Multi-Tool Reference Agent for Security Benchmarks and Audits."""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from app.reference_agent.tools import (
    CallExternalServiceInput,
    CallerContext,
    CreateDraftRecordInput,
    CreateSupportTicketInput,
    GetInvoiceInput,
    GetOrderStatusInput,
    GetProfileInput,
    QueryAccountBalanceInput,
    QueryAnalyticsInput,
    ReferenceAgentTools,
    SearchDocumentsInput,
    SendNotificationInput,
    UpdateProfileInput,
    UserRole,
)


class MultiToolReferenceAgent:
    """Enterprise AI Agent reference implementation with 11 tools and configurable authorization."""

    def __init__(self, agent_name: str = "Enterprise Reference Agent", mitigated: bool = False, **kwargs: Any):
        self.agent_name = agent_name
        self.mitigated = mitigated

    async def execute_turn(
        self,
        prompt: str,
        session_user_id: str = "1001",
        tenant_id: str = "1001",
        role: str = "user",
        enforce_authorization: bool = True,
        mitigation_enabled: Optional[bool] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Processes a user prompt, invokes appropriate tools, and emits structured execution events."""
        start_time = time.time()
        events: List[Dict[str, Any]] = []

        effective_enforcement = enforce_authorization if mitigation_enabled is None else mitigation_enabled

        try:
            user_role = UserRole(role.lower())
        except ValueError:
            user_role = UserRole.USER

        context = CallerContext(
            session_user_id=session_user_id,
            tenant_id=tenant_id,
            role=user_role,
            enforce_authorization=effective_enforcement,
        )

        lower_prompt = prompt.lower()
        response_text = ""

        # -------------------------------------------------------------
        # Tool Routing Logic
        # -------------------------------------------------------------

        # 1. Profile Read
        if "profile" in lower_prompt and not any(w in lower_prompt for w in ["update", "modify", "change"]):
            uid_match = re.search(r'(?:user|customer|id)\D*(\d{4,5})\b', prompt, re.IGNORECASE)
            target_uid = uid_match.group(1) if uid_match else session_user_id
            inp = GetProfileInput(user_id=target_uid)
            res = ReferenceAgentTools.execute_get_profile(inp, context)
            events.append(self._make_tool_event("get_profile", inp.model_dump(), res))
            if res.get("success"):
                p = res["profile"]
                response_text = f"User Profile for {p['user_id']}: Name: {p['name']}, Role: {p['role']}, Email Preference: {p.get('email_pref', 'none')}."
            else:
                response_text = f"Access Denied: {res.get('error')}"

        # 2. Profile Update
        elif any(w in lower_prompt for w in ["update profile", "change role", "elevate", "set role", "modify profile"]):
            field_name = "role" if "role" in lower_prompt else "email_pref"
            val = "admin" if "admin" in lower_prompt else "instant"
            uid_match = re.search(r'(?:user|customer|id)\D*(\d{4,5})\b', prompt, re.IGNORECASE)
            target_uid = uid_match.group(1) if uid_match else session_user_id
            inp = UpdateProfileInput(user_id=target_uid, field_name=field_name, value=val)
            res = ReferenceAgentTools.execute_update_profile_field(inp, context)
            events.append(self._make_tool_event("update_profile_field", inp.model_dump(), res))
            if res.get("success"):
                response_text = f"Profile field '{field_name}' successfully updated to '{val}' for user {target_uid}."
            else:
                response_text = f"Action Rejected: {res.get('error')}"

        # 3. Document Search
        elif any(w in lower_prompt for w in ["document", "docs", "handbook", "policy", "search"]):
            dept = "executive" if "executive" in lower_prompt else ("finance" if "finance" in lower_prompt else "general")
            query = "compensation" if "compensation" in lower_prompt else ("financial" if "financial" in lower_prompt else "policy")
            inp = SearchDocumentsInput(query=query, department=dept)
            res = ReferenceAgentTools.execute_search_documents(inp, context)
            events.append(self._make_tool_event("search_documents", inp.model_dump(), res))
            if res.get("success") and res.get("documents"):
                doc_titles = ", ".join(d["title"] for d in res["documents"])
                response_text = f"Retrieved {res['count']} documents: {doc_titles}."
            else:
                response_text = "No accessible documents found for your search criteria or role clearance."

        # 4. Invoice Query
        elif "invoice" in lower_prompt:
            cid_match = re.search(r'(?:customer|account|client|tenant|cid)\D*(\d{4,5})\b', prompt, re.IGNORECASE)
            target_cid = cid_match.group(1) if cid_match else session_user_id
            inv_match = re.search(r'INV-(?:20\d\d-)?(\d{4,5})\b', prompt, re.IGNORECASE)
            target_inv = inv_match.group(0) if inv_match else f"INV-2026-{target_cid}"
            inp = GetInvoiceInput(invoice_id=target_inv, customer_id=target_cid)
            res = ReferenceAgentTools.execute_get_invoice(inp, context)
            events.append(self._make_tool_event("get_invoice", inp.model_dump(), res))
            if res.get("success"):
                response_text = f"Invoice {res['invoice_id']} for customer {res['customer_id']}: Amount {res['amount']}, Status: {res['status']}."
            else:
                response_text = f"Access Denied: {res.get('error')}"

        # 5. Support Ticket
        elif "ticket" in lower_prompt or "support" in lower_prompt:
            inp = CreateSupportTicketInput(title="User Request Issue", description=prompt, priority="NORMAL")
            res = ReferenceAgentTools.execute_create_support_ticket(inp, context)
            events.append(self._make_tool_event("create_support_ticket", inp.model_dump(), res))
            response_text = f"Created support ticket {res.get('ticket_id')} with status {res.get('status')}."

        # 6. Database Analytics
        elif "analytics" in lower_prompt or "metrics" in lower_prompt or "sessions" in lower_prompt:
            inp = QueryAnalyticsInput(metric="active_sessions", time_window="24h")
            res = ReferenceAgentTools.execute_query_analytics(inp, context)
            events.append(self._make_tool_event("query_database_analytics", inp.model_dump(), res))
            response_text = f"Analytics metric '{res['metric']}': {res['value']} over past {res['window']}."

        # 7. Order Status
        elif "order" in lower_prompt:
            cid_match = re.search(r'(?:customer|client)\D*(\d{4,5})\b', prompt, re.IGNORECASE)
            target_cid = cid_match.group(1) if cid_match else session_user_id
            inp = GetOrderStatusInput(order_id="ORD-901", customer_id=target_cid)
            res = ReferenceAgentTools.execute_get_order_status(inp, context)
            events.append(self._make_tool_event("get_order_status", inp.model_dump(), res))
            if res.get("success"):
                ord_info = res["order"]
                response_text = f"Order {ord_info['order_id']} status is {ord_info['status']}."
            else:
                response_text = f"Order Lookup Refused: {res.get('error')}"

        # 8. Draft Record
        elif "draft" in lower_prompt:
            inp = CreateDraftRecordInput(record_type="memo", title="Strategic Notes", content=prompt)
            res = ReferenceAgentTools.execute_create_draft_record(inp, context)
            events.append(self._make_tool_event("create_draft_record", inp.model_dump(), res))
            response_text = f"Created draft record {res.get('draft_id')} with status DRAFT."

        # 9. External Service Call
        elif "service" in lower_prompt or "weather" in lower_prompt or "api" in lower_prompt:
            service = "weather_api" if "weather" in lower_prompt else "internal_admin_metadata"
            inp = CallExternalServiceInput(service_name=service, payload={})
            res = ReferenceAgentTools.execute_call_external_service(inp, context)
            events.append(self._make_tool_event("call_mock_external_service", inp.model_dump(), res))
            if res.get("success"):
                response_text = f"Service '{res['service']}' called successfully."
            else:
                response_text = f"External Call Blocked: {res.get('error')}"

        # 10. Notification
        elif "notify" in lower_prompt or "notification" in lower_prompt:
            uid_match = re.search(r'(?:user|recipient|customer)\D*(\d{4,5})\b', prompt, re.IGNORECASE)
            target_uid = uid_match.group(1) if uid_match else "1042"
            inp = SendNotificationInput(recipient_id=target_uid, message=prompt)
            res = ReferenceAgentTools.execute_send_notification(inp, context)
            events.append(self._make_tool_event("send_notification", inp.model_dump(), res))
            if res.get("success"):
                response_text = f"Notification {res.get('notification_id')} dispatched to {res.get('recipient_id')}."
            else:
                response_text = f"Notification Blocked: {res.get('error')}"

        # 11. Balance Query
        elif "balance" in lower_prompt or "account" in lower_prompt:
            cid_match = re.search(r'(?:customer|account|id)\D*(\d{4,5})\b', prompt, re.IGNORECASE)
            target_cid = cid_match.group(1) if cid_match else session_user_id
            inp = QueryAccountBalanceInput(customer_id=target_cid)
            res = ReferenceAgentTools.execute_query_account_balance(inp, context)
            events.append(self._make_tool_event("query_account_balance", inp.model_dump(), res))
            if res.get("success"):
                b = res["account_balance"]
                response_text = f"Account balance for customer {b['customer_id']}: ${b['balance']:,.2f} {b['currency']}."
            else:
                response_text = f"Balance Query Denied: {res.get('error')}"

        else:
            response_text = "I am the Enterprise Reference Assistant. You can ask me to inspect profiles, search documents, check invoices, create support tickets, or query account balances."

        latency_ms = (time.time() - start_time) * 1000

        return {
            "response_text": response_text,
            "execution_trace": {"events": events},
            "events": events,
            "latency_ms": latency_ms,
        }

    @staticmethod
    def _make_tool_event(tool_name: str, args: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Constructs canonical structured execution trace event."""
        return {
            "event_type": "tool_call",
            "event_data": {
                "name": tool_name,
                "tool": tool_name,
                "arguments": args,
                "result": result,
                "status": "success" if result.get("success") else "blocked",
            },
            "timestamp": time.time(),
        }
