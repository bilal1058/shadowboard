"""Authoritative security verdict engine.

Import from here rather than from the submodules so the public surface stays stable.
"""

from app.verdict.engine import (
    VerdictEngine,
    VerdictInputs,
    resolve,
    resolve_simple,
    verdict_counts,
)
from app.verdict.states import (
    CLEAN_VERDICTS,
    NON_PASSING_VERDICTS,
    SEVERITY_ORDER,
    UNRESOLVED_VERDICTS,
    VERDICT_PENALTY,
    VIOLATION_VERDICTS,
    EvidenceStrength,
    Severity,
    Verdict,
    count_penalty,
    is_clean,
    is_violation,
    max_severity,
    normalise_verdict,
    severity_weight,
    verdict_display,
)

__all__ = [
    "CLEAN_VERDICTS",
    "EvidenceStrength",
    "NON_PASSING_VERDICTS",
    "SEVERITY_ORDER",
    "Severity",
    "UNRESOLVED_VERDICTS",
    "VERDICT_PENALTY",
    "VIOLATION_VERDICTS",
    "Verdict",
    "VerdictEngine",
    "VerdictInputs",
    "count_penalty",
    "is_clean",
    "is_violation",
    "max_severity",
    "normalise_verdict",
    "resolve",
    "resolve_simple",
    "severity_weight",
    "verdict_counts",
    "verdict_display",
]
