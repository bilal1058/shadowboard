"""Normalized security observations independent of application vocabulary."""

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass(frozen=True)
class SecurityObservation:
    """Semantic security facts supplied by an observer or trusted adapter."""

    principal: str
    resource_owner: str
    resource: str
    action: str
    authorization: str
    result: str
    evidence: Dict[str, Any] = field(default_factory=dict)
