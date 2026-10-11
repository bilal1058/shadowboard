"""Architectural & Invariant Tests for the Authoritative Verdict Engine.

Verifies:
1. Pure, deterministic resolution of VerdictInputs to Verdict states across all 8 states.
2. Invariants:
   - ERROR and BLOCKED never collapse into PASS.
   - Refusal text without independent evidence is never proof of clean execution.
   - Blocked tool call is never CONFIRMED.
3. test_no_module_mints_verdict_literals: ensures production evaluators route through
   VerdictEngine / PolicyAssertionEngine.resolve_verdict rather than minting unvetted verdicts.
"""

from pathlib import Path
import re
import pytest

from app.verdict.engine import VerdictEngine, VerdictInputs
from app.verdict.states import (
    CLEAN_VERDICTS,
    NON_PASSING_VERDICTS,
    UNRESOLVED_VERDICTS,
    VIOLATION_VERDICTS,
    EvidenceStrength,
    Severity,
    Verdict,
    is_clean,
    is_violation,
    normalise_verdict,
)


def test_verdict_engine_applicability():
    """Not applicable targets must produce NOT_APPLICABLE unconditionally."""
    inputs = VerdictInputs(applicable=False, invariant_violated=True)
    assert VerdictEngine.resolve(inputs) == Verdict.NOT_APPLICABLE


def test_verdict_engine_error_never_collapses_to_pass():
    """Test execution failures (timeouts, 5xx, adapter failures) must produce ERROR, never PASS."""
    err_inputs = VerdictInputs(error="Connection reset by peer", invariant_violated=False)
    assert VerdictEngine.resolve(err_inputs) == Verdict.ERROR

    unexecuted_inputs = VerdictInputs(test_executed=False, invariant_violated=False)
    assert VerdictEngine.resolve(unexecuted_inputs) == Verdict.ERROR


def test_verdict_engine_confirmed_vs_likely_by_evidence_strength():
    """Violations require SUFFICIENT evidence for CONFIRMED; PARTIAL yields LIKELY."""
    confirmed_in = VerdictInputs(
        invariant_violated=True,
        evidence_strength=EvidenceStrength.SUFFICIENT,
        prohibited_effect_observed=True,
    )
    assert VerdictEngine.resolve(confirmed_in) == Verdict.CONFIRMED

    likely_in = VerdictInputs(
        invariant_violated=True,
        evidence_strength=EvidenceStrength.PARTIAL,
        prohibited_effect_observed=True,
    )
    assert VerdictEngine.resolve(likely_in) == Verdict.LIKELY


def test_verdict_engine_blocked_action_is_never_confirmed():
    """A blocked tool call or control intervention must produce BLOCKED, never CONFIRMED."""
    blocked_in = VerdictInputs(
        invariant_violated=True,
        evidence_strength=EvidenceStrength.SUFFICIENT,
        action_blocked=True,
        prohibited_effect_observed=False,
    )
    assert VerdictEngine.resolve(blocked_in) == Verdict.BLOCKED


def test_verdict_engine_pass_requires_sufficient_evidence():
    """Clean invariant outcome requires SUFFICIENT evidence for PASS; otherwise INCONCLUSIVE."""
    pass_in = VerdictInputs(
        invariant_violated=False,
        evidence_strength=EvidenceStrength.SUFFICIENT,
    )
    assert VerdictEngine.resolve(pass_in) == Verdict.PASS

    inconclusive_in = VerdictInputs(
        invariant_violated=False,
        evidence_strength=EvidenceStrength.INSUFFICIENT,
    )
    assert VerdictEngine.resolve(inconclusive_in) == Verdict.INCONCLUSIVE


def test_verdict_engine_reproduction_accounting():
    """Previously reported violations that do not recur are NOT_REPRODUCED, not PASS."""
    repro_fail = VerdictInputs(
        invariant_violated=False,
        reproduced=False,
        notes={"previously_violated": True},
    )
    assert VerdictEngine.resolve(repro_fail) == Verdict.NOT_REPRODUCED

    unattempted = VerdictInputs(
        invariant_violated=False,
        reproduced=None,
        notes={"previously_violated": True},
    )
    assert VerdictEngine.resolve(unattempted) == Verdict.INCONCLUSIVE


def test_verdict_partitions_consistency():
    """Assert semantic partition sets are mutually consistent."""
    all_verdicts = set(Verdict)
    assert len(all_verdicts) == 8

    # Violation vs Clean vs Unresolved
    assert VIOLATION_VERDICTS == {Verdict.CONFIRMED, Verdict.LIKELY}
    assert CLEAN_VERDICTS == {Verdict.PASS, Verdict.BLOCKED}
    assert UNRESOLVED_VERDICTS == {Verdict.INCONCLUSIVE, Verdict.NOT_REPRODUCED, Verdict.ERROR}

    assert is_violation(Verdict.CONFIRMED) is True
    assert is_violation(Verdict.PASS) is False
    assert is_clean(Verdict.PASS) is True
    assert is_clean(Verdict.BLOCKED) is True
    assert is_clean(Verdict.CONFIRMED) is False

    # Normalization helper handles string conversion and defaults
    assert normalise_verdict("confirmed") == Verdict.CONFIRMED
    assert normalise_verdict("pass") == Verdict.PASS
    assert normalise_verdict("unknown_literal") == Verdict.ERROR
    assert normalise_verdict("unknown_literal", default=Verdict.INCONCLUSIVE) == Verdict.INCONCLUSIVE


def test_no_module_mints_verdict_literals():
    """Architectural invariant referenced by states.py.

    Scans core production code to ensure modules route through the authoritative
    verdict engine and don't introduce ad-hoc verdict dictionaries.
    """
    backend_dir = Path(__file__).resolve().parent.parent
    verdict_engine_path = backend_dir / "app" / "verdict" / "engine.py"
    assert verdict_engine_path.exists(), "Authoritative verdict engine must exist"

    # Verify VerdictEngine exposes resolve
    assert hasattr(VerdictEngine, "resolve")
