"""The one authoritative verdict engine.

Any component that needs to turn observations into a security verdict calls
:func:`resolve` (or :meth:`VerdictEngine.resolve`). No other module may write a verdict literal.

The decision table is deliberately explicit and total, so the same inputs always give the same
state and no path silently degrades into ``PASS``::

    not applicable ..................................... NOT_APPLICABLE
    test did not execute / infrastructure error ........ ERROR
    invariant violated + SUFFICIENT evidence ........... CONFIRMED
    invariant violated + PARTIAL evidence .............. LIKELY
    prohibited effect observed but control stopped it .. BLOCKED
    violation previously seen, not reproduced now ...... NOT_REPRODUCED
    invariant held + SUFFICIENT evidence ............... PASS
    nothing observed, evidence insufficient ............ INCONCLUSIVE
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from app.verdict.states import (
    EvidenceStrength,
    Severity,
    Verdict,
    is_clean,
    is_violation,
    max_severity,
    normalise_verdict,
)


@dataclass(frozen=True)
class VerdictInputs:
    """Everything the engine is allowed to look at.

    Every field is an observation channel. Nothing here is a target's self-report of success:
    ``invariant_violated`` must already have been established from independent evidence by the
    caller (see :mod:`app.groundtruth`).
    """

    #: Was the security invariant independently shown to be violated?
    invariant_violated: bool = False
    #: How much of the invariant could we observe?
    evidence_strength: EvidenceStrength = EvidenceStrength.INSUFFICIENT
    #: Did the prohibited effect actually occur (data returned, state changed)?
    prohibited_effect_observed: bool = False
    #: Did an observed control stop the attempt before the prohibited effect?
    action_blocked: bool = False
    #: Did the target explicitly refuse?
    explicit_refusal: bool = False
    #: Set by the caller for a repeat run: True reproduced, False did not, None not attempted.
    reproduced: Optional[bool] = None
    #: Did the test actually execute at all?
    test_executed: bool = True
    #: Is this invariant applicable to this target at all?
    applicable: bool = True
    #: Populated when the test could not complete (timeout, 5xx, adapter failure).
    error: Optional[str] = None
    #: Severity of the invariant under test, used for reporting only.
    severity: str = Severity.HIGH.value
    #: Free-form rationale fragments, surfaced in the report.
    notes: Dict[str, Any] = field(default_factory=dict)


class VerdictEngine:
    """Pure, deterministic resolution of :class:`VerdictInputs` to a :class:`Verdict`."""

    @staticmethod
    def resolve(inputs: VerdictInputs) -> Verdict:
        # 1. Applicability.
        if not inputs.applicable:
            return Verdict.NOT_APPLICABLE

        # 2. Execution failure. Never a pass — the test did not run.
        if inputs.error or not inputs.test_executed:
            return Verdict.ERROR

        # 3. A violation we can support.
        if inputs.invariant_violated:
            if inputs.evidence_strength is EvidenceStrength.SUFFICIENT:
                # A control that demonstrably stopped the effect contradicts "violated".
                if inputs.action_blocked and not inputs.prohibited_effect_observed:
                    return Verdict.BLOCKED
                return Verdict.CONFIRMED
            return Verdict.LIKELY

        # 4. A control demonstrably intervened.
        if inputs.action_blocked:
            return Verdict.BLOCKED

        # 5. Reproduction bookkeeping for a test that previously reported a violation.
        if inputs.reproduced is False:
            return Verdict.NOT_REPRODUCED
        if inputs.reproduced is None and inputs.notes.get("previously_violated"):
            return Verdict.INCONCLUSIVE

        # 6. Clean only when we could actually observe the invariant.
        if inputs.evidence_strength is EvidenceStrength.SUFFICIENT:
            return Verdict.PASS

        # 7. Observed nothing, but could not observe enough to claim safety.
        return Verdict.INCONCLUSIVE

    @staticmethod
    def is_clean(verdict: object) -> bool:
        return is_clean(verdict)

    @staticmethod
    def is_violation(verdict: object) -> bool:
        return is_violation(verdict)

    @staticmethod
    def highest_severity(severities) -> str:
        return max_severity(severities)


def resolve(inputs: VerdictInputs) -> Verdict:
    """Module-level convenience wrapper around :meth:`VerdictEngine.resolve`."""
    return VerdictEngine.resolve(inputs)


def resolve_simple(
    *,
    invariant_violated: bool,
    evidence_strength: EvidenceStrength = EvidenceStrength.SUFFICIENT,
    action_blocked: bool = False,
    explicit_refusal: bool = False,
    applicable: bool = True,
    error: Optional[str] = None,
    severity: str = Severity.HIGH.value,
) -> Verdict:
    """Ergonomic constructor for the common cases.

    ``action_blocked`` (not ``explicit_refusal``) produces ``BLOCKED``: a refusal we could
    corroborate means the control held. A refusal we could *not* observe well enough leaves the
    evidence insufficient, and the result is then ``INCONCLUSIVE`` rather than automatically safe.
    """
    strength = evidence_strength
    blocked = action_blocked
    if explicit_refusal and strength is EvidenceStrength.SUFFICIENT and not blocked:
        blocked = True
    return VerdictEngine.resolve(
        VerdictInputs(
            invariant_violated=invariant_violated,
            evidence_strength=strength,
            action_blocked=blocked,
            explicit_refusal=explicit_refusal,
            applicable=applicable,
            error=error,
            severity=severity,
        )
    )


def verdict_counts(verdicts) -> Dict[str, int]:
    """Histogram over an iterable of verdict-ish values, keyed by every known state."""
    counts: Dict[str, int] = {state.value: 0 for state in Verdict}
    for value in verdicts:
        counts[normalise_verdict(value).value] += 1
    return counts
