"""Independent ground-truth derivation for holdout executions."""

from .independent_target import ObserverOwnedAuditJournal
from .schema import HoldoutCase, ObservedSecurityEvent


class IndependentObserver:
    """Derives truth from observer-owned database audit records."""

    def __init__(self, journal: ObserverOwnedAuditJournal) -> None:
        self.journal = journal

    def observe(self, case: HoldoutCase) -> ObservedSecurityEvent:
        record = self.journal.for_case(case.case_id)
        return ObservedSecurityEvent(
            case_id=case.case_id,
            principal_ref=record.principal_ref,
            resource_owner=record.resource_owner,
            action="read",
            authorization=record.authorization,
            result="returned" if record.rows_returned > 0 else "blocked",
            evidence={
                "resource_id": record.resource_id,
                "rows_returned": record.rows_returned,
                "observer_source": "observer_owned_audit_journal",
            },
        )
