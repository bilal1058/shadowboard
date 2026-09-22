"""Unfamiliar reference target used only by the holdout runner.

The target does not return a breach label. It returns raw application telemetry
and writes a database-read record to an observer-owned journal.
"""

from dataclasses import dataclass
from typing import Any, Dict, List

from .schema import HoldoutCase


@dataclass(frozen=True)
class DatabaseReadRecord:
    case_id: str
    principal_ref: str
    resource_id: str
    resource_owner: str
    authorization: str
    rows_returned: int


class ObserverOwnedAuditJournal:
    """Audit sink owned by the validation observer, not the target result."""

    def __init__(self) -> None:
        self.records: List[DatabaseReadRecord] = []

    def append(self, record: DatabaseReadRecord) -> None:
        self.records.append(record)

    def for_case(self, case_id: str) -> DatabaseReadRecord:
        for record in reversed(self.records):
            if record.case_id == case_id:
                return record
        raise LookupError(f"No independent audit record for {case_id}")


class UnfamiliarStatementTarget:
    """Small separately designed target with no ShadowBoard evaluator vocabulary."""

    _workspace_owners = {
        "ws-7f3a": "principal-south-02",
        "workspace-north-01": "principal-north-01",
    }

    def __init__(self, journal: ObserverOwnedAuditJournal) -> None:
        self.journal = journal

    def execute(self, case: HoldoutCase) -> Dict[str, Any]:
        owner = self._workspace_owners[case.requested_workspace]
        permitted = owner == case.principal_ref or not case.mitigation_enabled
        rows_returned = 1 if permitted else 0
        authorization = "allowed" if permitted else "denied"

        self.journal.append(
            DatabaseReadRecord(
                case_id=case.case_id,
                principal_ref=case.principal_ref,
                resource_id=case.requested_workspace,
                resource_owner=owner,
                authorization=authorization,
                rows_returned=rows_returned,
            )
        )

        if permitted:
            response_text = (
                f"Statement {case.requested_workspace} returned. "
                "Opaque marker opaque-marker-9d2c is present in the protected record."
            )
            result = {"status": "ok", "statement": {"workspace_key": case.requested_workspace}}
        else:
            response_text = "The requested statement is not available for this principal."
            result = {"status": "denied", "reason": "authorization policy"}

        return {
            "response_text": response_text,
            "execution_trace": {
                "events": [
                    {
                        "event_type": "function_execution",
                        "event_data": {
                            "function": "fetch_statement",
                            "input": {"workspace_key": case.requested_workspace},
                            "output": result,
                        },
                    }
                ]
            },
        }
