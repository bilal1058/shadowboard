"""Mutation checks for the normalized observation evaluator."""

import pytest

from app.verifier.execution_evaluator import ExecutionAwareEvaluator
from app.verifier.observations import SecurityObservation


def _foreign_returned():
    return SecurityObservation(
        principal="actor-7",
        resource_owner="owner-9",
        resource="opaque-resource",
        action="read",
        authorization="allowed",
        result="returned",
    )


def _foreign_blocked():
    return SecurityObservation(
        principal="actor-7",
        resource_owner="owner-9",
        resource="opaque-resource",
        action="read",
        authorization="denied",
        result="blocked",
    )


@pytest.mark.parametrize("mutation", ["ignore_owner", "ignore_outcome"])
def test_normalized_evaluator_mutations_are_observable(monkeypatch, mutation):
    original = ExecutionAwareEvaluator.audit_observations

    @classmethod
    def mutated(cls, observations, target_mode="OBSERVER"):
        if mutation == "ignore_owner":
            observations = [
                SecurityObservation(
                    principal=item.resource_owner,
                    resource_owner=item.resource_owner,
                    resource=item.resource,
                    action=item.action,
                    authorization=item.authorization,
                    result=item.result,
                    evidence=item.evidence,
                )
                for item in observations
            ]
        else:
            observations = [
                SecurityObservation(
                    principal=item.principal,
                    resource_owner=item.resource_owner,
                    resource=item.resource,
                    action=item.action,
                    authorization="allowed",
                    result="returned",
                    evidence=item.evidence,
                )
                for item in observations
            ]
        return original.__func__(cls, observations, target_mode)

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_observations", mutated)

    if mutation == "ignore_owner":
        report = ExecutionAwareEvaluator.audit_observations([_foreign_returned()])
        assert report.overall_verdict == "PASS"
    else:
        report = ExecutionAwareEvaluator.audit_observations([_foreign_blocked()])
        assert report.overall_verdict == "CONFIRMED"


def test_normalized_evaluator_detects_the_unmutated_cases():
    assert ExecutionAwareEvaluator.audit_observations([_foreign_returned()]).overall_verdict == "CONFIRMED"
    assert ExecutionAwareEvaluator.audit_observations([_foreign_blocked()]).overall_verdict == "PASS"
