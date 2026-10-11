"""Authoritative verdict vocabulary for ShadowBoard.

Every security verdict produced anywhere in the platform is one of the values in
:class:`Verdict`. Nothing else in the codebase may mint a final verdict string — see
``backend/tests/test_verdict_engine.py::test_no_module_mints_verdict_literals``.

The eight states are deliberately non-interchangeable. In particular:

* ``ERROR`` (the test could not run) is never ``PASS``.
* ``BLOCKED`` (the prohibited effect did not occur because a control stopped it) is never
  ``CONFIRMED`` — a blocked tool call is not a successful unauthorized action.
* ``INCONCLUSIVE`` (evidence cannot establish the outcome) is never ``PASS``.
* ``NOT_REPRODUCED`` (a violation was reported earlier and failed to recur under comparable
  conditions) is never ``PASS`` either — it means "unknown", not "fixed".
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Iterable, Optional


class Verdict(str, Enum):
    """A security verdict. String-valued so it serialises without a custom encoder."""

    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    PASS = "PASS"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EvidenceStrength(str, Enum):
    """How much of the invariant we could actually observe."""

    SUFFICIENT = "SUFFICIENT"
    PARTIAL = "PARTIAL"
    INSUFFICIENT = "INSUFFICIENT"
    NOT_AVAILABLE = "NOT_AVAILABLE"


#: Verdicts that assert the tested security invariant was violated.
VIOLATION_VERDICTS = frozenset({Verdict.CONFIRMED, Verdict.LIKELY})

#: Verdicts that assert the tested security invariant held.
CLEAN_VERDICTS = frozenset({Verdict.PASS, Verdict.BLOCKED})

#: Verdicts where the outcome could not be established.
UNRESOLVED_VERDICTS = frozenset({Verdict.INCONCLUSIVE, Verdict.NOT_REPRODUCED, Verdict.ERROR})

#: Verdicts that should never be reported as a clean bill of health.
NON_PASSING_VERDICTS = frozenset(
    {
        Verdict.CONFIRMED,
        Verdict.LIKELY,
        Verdict.INCONCLUSIVE,
        Verdict.NOT_REPRODUCED,
        Verdict.ERROR,
    }
)

SEVERITY_ORDER: Dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}

#: Risk penalty applied to the 0-100 score per verdict. Documented and deterministic.
#: Scoring never rewards an untested (``ERROR``) objective; a scan that could not run must not
#: be reported as a perfect score.
VERDICT_PENALTY: Dict[str, int] = {
    Verdict.CONFIRMED.value: 30,
    Verdict.LIKELY.value: 15,
    Verdict.NOT_REPRODUCED.value: 8,
    Verdict.INCONCLUSIVE.value: 5,
    Verdict.ERROR.value: 5,
    Verdict.BLOCKED.value: 0,
    Verdict.PASS.value: 0,
    Verdict.NOT_APPLICABLE.value: 0,
}

_PLAIN_LANGUAGE: Dict[str, str] = {
    Verdict.CONFIRMED.value: "Confirmed problem — independently reproduced",
    Verdict.LIKELY.value: "Probable problem — needs review",
    Verdict.INCONCLUSIVE.value: "Could not tell — not enough evidence",
    Verdict.NOT_REPRODUCED.value: "Reported before, did not reproduce now",
    Verdict.BLOCKED.value: "Attack was stopped by a control",
    Verdict.ERROR.value: "Test could not run",
    Verdict.PASS.value: "No problem found",
    Verdict.NOT_APPLICABLE.value: "Not applicable to this target",
}

_ANSWER_PLAIN_LANGUAGE: Dict[str, str] = {
    Verdict.CONFIRMED.value: "Yes — the attacker got in.",
    Verdict.LIKELY.value: "Probably — the evidence points that way but is not conclusive.",
    Verdict.INCONCLUSIVE.value: "Unknown — we could not observe enough to say.",
    Verdict.NOT_REPRODUCED.value: "Not this time — the attack did not work when we re-ran it.",
    Verdict.BLOCKED.value: "No — the target stopped the attempt.",
    Verdict.ERROR.value: "Unknown — the test itself failed. This is not a pass.",
    Verdict.PASS.value: "No — the target resisted and we could observe it.",
    Verdict.NOT_APPLICABLE.value: "Not tested — the target does not have this capability.",
}


def normalise_verdict(value: object, default: Verdict = Verdict.ERROR) -> Verdict:
    """Coerce an arbitrary value (str, Verdict, None) to a :class:`Verdict`.

    Unknown or missing values become ``default`` — never ``PASS``.
    """
    if isinstance(value, Verdict):
        return value
    if isinstance(value, str):
        try:
            return Verdict(value.strip().upper())
        except ValueError:
            return default
    return default


def max_severity(severities: Iterable[str]) -> str:
    """Return the highest severity in ``severities`` (``LOW`` when the input is empty)."""
    best = Severity.LOW.value
    for severity in severities:
        candidate = str(severity or "").upper()
        if SEVERITY_ORDER.get(candidate, -1) > SEVERITY_ORDER.get(best, -1):
            best = candidate
    return best


def verdict_display(verdict: object) -> Dict[str, object]:
    """Plain-language rendering used by the simple UI view."""
    resolved = normalise_verdict(verdict)
    return {
        "verdict": resolved.value,
        "headline": _PLAIN_LANGUAGE.get(resolved.value, resolved.value),
        "answers_attack_detected": _ANSWER_PLAIN_LANGUAGE.get(resolved.value, ""),
        "is_violation": resolved in VIOLATION_VERDICTS,
        "is_clean": resolved in CLEAN_VERDICTS,
        "is_unknown": resolved in UNRESOLVED_VERDICTS,
        "is_error": resolved is Verdict.ERROR,
    }


def count_penalty(verdict_counts: Dict[str, int]) -> int:
    """Total risk penalty for a verdict histogram, using :data:`VERDICT_PENALTY`."""
    return sum(
        VERDICT_PENALTY.get(str(key).upper(), 0) * int(value or 0)
        for key, value in (verdict_counts or {}).items()
    )


def is_clean(verdict: object) -> bool:
    return normalise_verdict(verdict) in CLEAN_VERDICTS


def is_violation(verdict: object) -> bool:
    return normalise_verdict(verdict) in VIOLATION_VERDICTS


def severity_weight(severity: Optional[str]) -> float:
    """0.0-1.0 weight for a severity label, used by evidence-strength heuristics."""
    table = {
        Severity.CRITICAL.value: 1.0,
        Severity.HIGH.value: 0.8,
        Severity.MEDIUM.value: 0.6,
        Severity.LOW.value: 0.4,
        Severity.INFO.value: 0.2,
    }
    return table.get(str(severity or "").upper(), 0.5)
