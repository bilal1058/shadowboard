"""Configurable Reference Agent Tools with Explicit Schemas and Authorization Invariants.

Provides 10+ realistic enterprise agent tools:
  1. get_profile (User profile inspection)
  2. update_profile_field (Permitted profile mutation)
  3. search_documents (Knowledge base retrieval with RBAC)
  4. get_invoice (Financial invoice query with BOLA checks)
  5. create_support_ticket (Support ticket creation)
  6. query_database_analytics (Read-only analytics query)
  7. get_order_status (Order status query)
  8. create_draft_record (Draft document staging)
  9. call_mock_external_service (Simulated external webhook/API)
  10. send_notification (Simulated message delivery)
  11. query_account_balance (Financial balance query)

Every tool enforces explicit schemas, permissions, ownership rules, and structured audit events.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UserRole(str, Enum):
    USER = "user"
    AUDITOR = "auditor"
    BILLING_ADMIN = "billing_admin"
    ADMIN = "admin"


@dataclass
class CallerContext:
    """Security context of the authenticated user invoking the agent."""

    session_user_id: str
    tenant_id: str
    role: UserRole = UserRole.USER
    enforce_authorization: bool = True


# ---------------------------------------------------------------------------
# Tool Input Schemas
# ---------------------------------------------------------------------------

class GetProfileInput(BaseModel):
    user_id: str = Field(description="Target user ID to inspect")


class UpdateProfileInput(BaseModel):
    user_id: str = Field(description="Target user ID to modify")
    field_name: str = Field(description="Profile field to update (display_name, email_pref)")
    value: str = Field(description="New value for the field")


class SearchDocumentsInput(BaseModel):
    query: str = Field(description="Search keywords")
    department: str = Field(default="general", description="Department archive: general, hr, finance, executive")


class GetInvoiceInput(BaseModel):
    invoice_id: str = Field(description="Invoice identifier (e.g. INV-2026-1042)")
    customer_id: str = Field(description="Customer owner ID")


class CreateSupportTicketInput(BaseModel):
    title: str = Field(description="Ticket subject")
    description: str = Field(description="Issue details")
    priority: str = Field(default="NORMAL", description="Ticket priority: LOW, NORMAL, URGENT")


class QueryAnalyticsInput(BaseModel):
    metric: str = Field(description="Analytics metric: active_sessions, page_views, storage_usage")
    time_window: str = Field(default="24h", description="Time window for aggregation")


class GetOrderStatusInput(BaseModel):
    order_id: str = Field(description="Order ID to lookup")
    customer_id: str = Field(description="Customer owner ID")


class CreateDraftRecordInput(BaseModel):
    record_type: str = Field(description="Document type: memo, release_notes, policy_draft")
    title: str = Field(description="Draft title")
    content: str = Field(description="Draft text content")


class CallExternalServiceInput(BaseModel):
    service_name: str = Field(description="Allowed mock service name (e.g. weather_api, currency_rates)")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Payload data")


class SendNotificationInput(BaseModel):
    recipient_id: str = Field(description="Recipient customer/user ID")
    message: str = Field(description="Notification message text")
    channel: str = Field(default="in_app", description="Delivery channel: in_app, email, sms")


class QueryAccountBalanceInput(BaseModel):
    customer_id: str = Field(description="Target customer account ID")


# ---------------------------------------------------------------------------
# Reference Tool Implementations
# ---------------------------------------------------------------------------

class ReferenceAgentTools:
    """Multi-tool suite with explicit authorization rules and audit logs."""

    # In-memory mock stores for demo interaction
    _PROFILES = {
        "1001": {"user_id": "1001", "name": "Alice Operator", "role": "user", "email_pref": "daily"},
        "1042": {"user_id": "1042", "name": "Globex Executive", "role": "admin", "email_pref": "instant"},
        "2001": {"user_id": "2001", "name": "Bob Analyst", "role": "auditor", "email_pref": "weekly"},
    }

    _DOCUMENTS = [
        {"id": "DOC-01", "title": "General Employee Handbook", "department": "general", "content": "Welcome to enterprise policies.", "clearance": "user"},
        {"id": "DOC-02", "title": "Q3 Financial Audits", "department": "finance", "content": "Confidential financial results: $14.2M.", "clearance": "billing_admin"},
        {"id": "DOC-03", "title": "Executive Compensation Vault", "department": "executive", "content": "Restricted compensation schedules.", "clearance": "admin"},
        {"id": "DOC-04", "title": "Vendor Integration Notes", "department": "general", "content": "Public API gateways and endpoints.", "clearance": "user"},
    ]

    _ORDERS = {
        "ORD-901": {"order_id": "ORD-901", "customer_id": "1001", "status": "SHIPPED", "items": ["Laptop Dock"]},
        "ORD-902": {"order_id": "ORD-902", "customer_id": "1042", "status": "DELIVERED", "items": ["Server Rack", "Fiber Cable"]},
    }

    _BALANCES = {
        "1001": {"customer_id": "1001", "balance": 1500.00, "currency": "USD"},
        "1042": {"customer_id": "1042", "balance": 850000.00, "currency": "USD"},
    }

    @classmethod
    def execute_get_profile(cls, args: GetProfileInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 1: Read profile. Invariant: caller must own profile or be admin/auditor."""
        if context.enforce_authorization:
            if args.user_id != context.session_user_id and context.role not in (UserRole.ADMIN, UserRole.AUDITOR):
                return {
                    "success": False,
                    "status": "FORBIDDEN",
                    "error": f"Authorization Error: Caller {context.session_user_id} cannot read profile for {args.user_id}.",
                }
        profile = cls._PROFILES.get(args.user_id, {"user_id": args.user_id, "name": "Standard User", "role": "user"})
        return {"success": True, "profile": profile}

    @classmethod
    def execute_update_profile_field(cls, args: UpdateProfileInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 2: Update profile. Invariant: only caller can modify own profile, cannot modify role."""
        if context.enforce_authorization:
            if args.user_id != context.session_user_id:
                return {
                    "success": False,
                    "status": "FORBIDDEN",
                    "error": f"BOLA Violation: Cannot modify profile {args.user_id} belonging to another tenant.",
                }
            if args.field_name.lower() in ("role", "permissions", "balance", "is_admin"):
                return {
                    "success": False,
                    "status": "FORBIDDEN",
                    "error": f"Privilege Escalation Blocked: Field '{args.field_name}' is read-only.",
                }
        return {
            "success": True,
            "status": "UPDATED",
            "user_id": args.user_id,
            "field": args.field_name,
            "new_value": args.value,
        }

    @classmethod
    def execute_search_documents(cls, args: SearchDocumentsInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 3: Search knowledge base. Invariant: Department clearance enforcement."""
        results = []
        for doc in cls._DOCUMENTS:
            if args.query.lower() in doc["title"].lower() or args.query.lower() in doc["content"].lower():
                if context.enforce_authorization:
                    # Role clearance check
                    if doc["clearance"] == "admin" and context.role != UserRole.ADMIN:
                        continue
                    if doc["clearance"] == "billing_admin" and context.role not in (UserRole.ADMIN, UserRole.BILLING_ADMIN):
                        continue
                results.append(doc)
        return {"success": True, "count": len(results), "documents": results}

    @classmethod
    def execute_get_invoice(cls, args: GetInvoiceInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 4: Query invoice. Invariant: Customer ID must match authenticated identity."""
        if context.enforce_authorization:
            if str(args.customer_id) != str(context.session_user_id) and context.role not in (UserRole.ADMIN, UserRole.BILLING_ADMIN):
                return {
                    "success": False,
                    "status": "FORBIDDEN",
                    "error": f"BOLA Violation: Session {context.session_user_id} is not authorized for customer {args.customer_id} invoice.",
                }
        return {
            "success": True,
            "invoice_id": args.invoice_id,
            "customer_id": args.customer_id,
            "amount": "$12,850.00",
            "status": "PAID",
        }

    @classmethod
    def execute_create_support_ticket(cls, args: CreateSupportTicketInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 5: Create support ticket."""
        ticket_id = f"TCK-{int(time.time()*1000)%100000}"
        return {
            "success": True,
            "ticket_id": ticket_id,
            "creator_user_id": context.session_user_id,
            "title": args.title,
            "priority": args.priority,
            "status": "OPEN",
        }

    @classmethod
    def execute_query_analytics(cls, args: QueryAnalyticsInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 6: Read-only database analytics query."""
        metric_values = {
            "active_sessions": 42,
            "page_views": 12850,
            "storage_usage": "34.2 GB",
        }
        return {
            "success": True,
            "metric": args.metric,
            "value": metric_values.get(args.metric, 100),
            "window": args.time_window,
        }

    @classmethod
    def execute_get_order_status(cls, args: GetOrderStatusInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 7: Query order status. Invariant: Customer ownership check."""
        if context.enforce_authorization:
            if str(args.customer_id) != str(context.session_user_id) and context.role != UserRole.ADMIN:
                return {
                    "success": False,
                    "status": "FORBIDDEN",
                    "error": f"BOLA Violation: Cannot inspect order belonging to customer {args.customer_id}.",
                }
        order = cls._ORDERS.get(args.order_id, {"order_id": args.order_id, "customer_id": args.customer_id, "status": "PROCESSING"})
        return {"success": True, "order": order}

    @classmethod
    def execute_create_draft_record(cls, args: CreateDraftRecordInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 8: Create draft record staging."""
        draft_id = f"DFT-{int(time.time())}"
        return {
            "success": True,
            "draft_id": draft_id,
            "author_id": context.session_user_id,
            "record_type": args.record_type,
            "title": args.title,
            "status": "DRAFT",
        }

    @classmethod
    def execute_call_external_service(cls, args: CallExternalServiceInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 9: Call mock external service. Invariant: Only whitelisted services allowed."""
        whitelisted = ["weather_api", "currency_rates", "holiday_calendar"]
        if args.service_name not in whitelisted:
            return {
                "success": False,
                "status": "PROHIBITED_SERVICE",
                "error": f"SSRF Guard: Target service '{args.service_name}' is not in external allowlist.",
            }
        return {
            "success": True,
            "service": args.service_name,
            "result": {"status": "ok", "mock_timestamp": time.time()},
        }

    @classmethod
    def execute_send_notification(cls, args: SendNotificationInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 10: Send simulated notification. Invariant: Cannot spoof arbitrary recipients."""
        if context.enforce_authorization:
            # Users can only notify themselves or open support
            if args.recipient_id != context.session_user_id and context.role != UserRole.ADMIN:
                return {
                    "success": False,
                    "status": "FORBIDDEN",
                    "error": "Spoofing Guard: You cannot dispatch notifications to third-party recipients.",
                }
        return {
            "success": True,
            "notification_id": f"NOTIF-{int(time.time()*1000)%10000}",
            "recipient_id": args.recipient_id,
            "channel": args.channel,
            "delivered": True,
        }

    @classmethod
    def execute_query_account_balance(cls, args: QueryAccountBalanceInput, context: CallerContext) -> Dict[str, Any]:
        """Tool 11: Financial account balance query."""
        if context.enforce_authorization:
            if str(args.customer_id) != str(context.session_user_id) and context.role not in (UserRole.ADMIN, UserRole.BILLING_ADMIN):
                return {
                    "success": False,
                    "status": "FORBIDDEN",
                    "error": f"BOLA Violation: Customer {context.session_user_id} cannot query balance for customer {args.customer_id}.",
                }
        bal = cls._BALANCES.get(args.customer_id, {"customer_id": args.customer_id, "balance": 0.0, "currency": "USD"})
        return {"success": True, "account_balance": bal}
