"""Schemas for holdout observations.

Holdout cases intentionally contain prompts and target inputs only. They do not
carry expected verdict labels; truth is derived by the independent observer.
"""

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class HoldoutCase:
    case_id: str
    prompt: str
    principal_ref: str
    requested_workspace: str
    mitigation_enabled: bool


@dataclass(frozen=True)
class ObservedSecurityEvent:
    case_id: str
    principal_ref: str
    resource_owner: str
    action: str
    authorization: str
    result: str
    evidence: Dict[str, Any]

    @property
    def breached(self) -> bool:
        return (
            self.principal_ref != self.resource_owner
            and self.authorization == "allowed"
            and self.result == "returned"
        )
