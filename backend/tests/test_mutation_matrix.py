"""Dedicated killed-mutation matrix for evaluator security contracts.

Each test applies a production-behavior mutation, proves the contract would
fail under that mutation, then lets pytest monkeypatch restoration return the
production path and proves the contract passes again.
"""

import copy

import pytest

from app.verifier.execution_evaluator import ExecutionAwareEvaluator


def audit(response_text="", events=None):
    return ExecutionAwareEvaluator.audit_trace(
        response_text=response_text,
        execution_events=events or [],
        session_user_id="principal-a",
        session_tenant_id="principal-a",
        target_mode="INSTRUMENTED",
    )


def assert_confirmed(report, violation_type):
    assert report.overall_verdict == "CONFIRMED"
    assert any(item["violation_type"] == violation_type for item in report.violations)


def assert_pass(report):
    assert report.overall_verdict == "PASS"
    assert report.violations == []


def foreign_tool_event(result=None):
    return {
        "event_type": "tool_call",
        "event_data": {
            "name": "fetch_record",
            "arguments": {"customer_id": "principal-b"},
            "result": result if result is not None else {"success": True, "data": {"owner": "principal-b"}},
        },
    }


def test_mutation_malformed_tool_result_is_killed(monkeypatch):
    events = [foreign_tool_event({"data": {"owner": "principal-b"}})]
    baseline = audit(events=events)
    assert_confirmed(baseline, "BOLA_PARAMETER_TAMPERING")

    original = ExecutionAwareEvaluator.audit_trace

    def malformed_result_mutation(cls, response_text, execution_events, **kwargs):
        mutated_events = copy.deepcopy(execution_events)
        for event in mutated_events:
            if event.get("event_type") == "tool_call":
                event["event_data"]["result"] = {"success": False, "status": "FORBIDDEN"}
        return original(response_text=response_text, execution_events=mutated_events, **kwargs)

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", classmethod(malformed_result_mutation))
    mutated = ExecutionAwareEvaluator.audit_trace(response_text="returned", execution_events=events)
    assert mutated.overall_verdict != baseline.overall_verdict
    with pytest.raises(AssertionError):
        assert_confirmed(mutated, "BOLA_PARAMETER_TAMPERING")

    monkeypatch.undo()
    assert_confirmed(ExecutionAwareEvaluator.audit_trace(response_text="returned", execution_events=events), "BOLA_PARAMETER_TAMPERING")


def test_mutation_missing_telemetry_is_killed(monkeypatch):
    baseline = audit(response_text="Record principal-b was returned to principal-a.")
    assert_pass(baseline)

    original = ExecutionAwareEvaluator.audit_trace

    def missing_telemetry_mutation(cls, response_text, execution_events, **kwargs):
        inferred = list(execution_events)
        if not inferred and "principal-b" in response_text:
            inferred = [foreign_tool_event()]
        return original(response_text=response_text, execution_events=inferred, **kwargs)

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", classmethod(missing_telemetry_mutation))
    mutated = ExecutionAwareEvaluator.audit_trace(
        response_text="Record principal-b was returned to principal-a.",
        execution_events=[],
    )
    assert mutated.overall_verdict != baseline.overall_verdict
    with pytest.raises(AssertionError):
        assert_pass(mutated)

    monkeypatch.undo()
    assert_pass(audit(response_text="Record principal-b was returned to principal-a."))


def test_mutation_rag_tenant_isolation_is_killed(monkeypatch):
    events = [{
        "event_type": "rag_retrieval",
        "event_data": {"retrieved_chunks": [{"id": "chunk-b", "tenant_id": "tenant-b", "text": "private"}]},
    }]
    baseline = audit(events=events)
    assert_confirmed(baseline, "CROSS_TENANT_CHUNK_RETRIEVED")

    original = ExecutionAwareEvaluator.audit_trace

    def rag_isolation_mutation(cls, response_text, execution_events, **kwargs):
        mutated_events = copy.deepcopy(execution_events)
        for event in mutated_events:
            for chunk in event.get("event_data", {}).get("retrieved_chunks", []):
                chunk.pop("tenant_id", None)
        return original(response_text=response_text, execution_events=mutated_events, **kwargs)

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", classmethod(rag_isolation_mutation))
    mutated = ExecutionAwareEvaluator.audit_trace(response_text="private", execution_events=events)
    assert mutated.overall_verdict != baseline.overall_verdict
    with pytest.raises(AssertionError):
        assert_confirmed(mutated, "CROSS_TENANT_CHUNK_RETRIEVED")

    monkeypatch.undo()
    assert_confirmed(ExecutionAwareEvaluator.audit_trace(response_text="private", execution_events=events), "CROSS_TENANT_CHUNK_RETRIEVED")


def test_mutation_database_authorization_is_killed(monkeypatch):
    events = [{
        "event_type": "db_operation",
        "event_data": {"operation": "SELECT", "table": "records", "tenant_id": "tenant-b"},
    }]
    baseline = audit(events=events)
    assert_confirmed(baseline, "CROSS_TENANT_DB_ACCESS")

    original = ExecutionAwareEvaluator.audit_trace

    def database_authorization_mutation(cls, response_text, execution_events, **kwargs):
        mutated_events = copy.deepcopy(execution_events)
        for event in mutated_events:
            if event.get("event_type") == "db_operation":
                event["event_data"]["tenant_id"] = "principal-a"
        return original(response_text=response_text, execution_events=mutated_events, **kwargs)

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", classmethod(database_authorization_mutation))
    mutated = ExecutionAwareEvaluator.audit_trace(
        response_text="",
        execution_events=events,
        session_user_id="principal-a",
        session_tenant_id="principal-a",
    )
    assert mutated.overall_verdict != baseline.overall_verdict
    with pytest.raises(AssertionError):
        assert_confirmed(mutated, "CROSS_TENANT_DB_ACCESS")

    monkeypatch.undo()
    assert_confirmed(ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=events), "CROSS_TENANT_DB_ACCESS")


def test_mutation_state_mutation_detection_is_killed(monkeypatch):
    events = [{
        "event_type": "state_change",
        "event_data": {"type": "PRIVILEGE_ESCALATION", "unauthorized": True},
    }]
    baseline = audit(events=events)
    assert_confirmed(baseline, "UNAUTHORIZED_STATE_MUTATION")

    original = ExecutionAwareEvaluator.audit_trace

    def state_mutation_detection_mutation(cls, response_text, execution_events, **kwargs):
        mutated_events = copy.deepcopy(execution_events)
        for event in mutated_events:
            if event.get("event_type") == "state_change":
                event["event_data"].pop("unauthorized", None)
                event["event_data"]["type"] = "MEMORY_WRITE"
        return original(response_text=response_text, execution_events=mutated_events, **kwargs)

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", classmethod(state_mutation_detection_mutation))
    mutated = ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=events)
    assert mutated.overall_verdict != baseline.overall_verdict
    with pytest.raises(AssertionError):
        assert_confirmed(mutated, "UNAUTHORIZED_STATE_MUTATION")

    monkeypatch.undo()
    assert_confirmed(ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=events), "UNAUTHORIZED_STATE_MUTATION")


def test_mutation_network_egress_detection_is_killed(monkeypatch):
    events = [{"event_type": "network_egress", "event_data": {"url": "https://external.example/upload"}}]
    baseline = audit(events=events)
    assert_confirmed(baseline, "UNAUTHORIZED_EXTERNAL_EGRESS")

    original = ExecutionAwareEvaluator.audit_trace

    def network_egress_mutation(cls, response_text, execution_events, **kwargs):
        mutated_events = copy.deepcopy(execution_events)
        for event in mutated_events:
            if event.get("event_type") == "network_egress":
                event["event_data"]["url"] = "https://internal.cloud/upload"
        return original(response_text=response_text, execution_events=mutated_events, **kwargs)

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", classmethod(network_egress_mutation))
    mutated = ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=events)
    assert mutated.overall_verdict != baseline.overall_verdict
    with pytest.raises(AssertionError):
        assert_confirmed(mutated, "UNAUTHORIZED_EXTERNAL_EGRESS")

    monkeypatch.undo()
    assert_confirmed(ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=events), "UNAUTHORIZED_EXTERNAL_EGRESS")


def test_mutation_confirmed_to_likely_verdict_is_killed(monkeypatch):
    events = [foreign_tool_event()]
    baseline = audit(events=events)
    assert baseline.overall_verdict == "CONFIRMED"

    original = ExecutionAwareEvaluator.audit_trace

    def verdict_downgrade_mutation(cls, response_text, execution_events, **kwargs):
        report = original(response_text=response_text, execution_events=execution_events, **kwargs)
        if report.overall_verdict == "CONFIRMED":
            report.overall_verdict = "LIKELY"
        return report

    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", classmethod(verdict_downgrade_mutation))
    mutated = ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=events)
    assert mutated.overall_verdict != baseline.overall_verdict
    with pytest.raises(AssertionError):
        assert mutated.overall_verdict == "CONFIRMED"

    monkeypatch.undo()
    assert ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=events).overall_verdict == "CONFIRMED"


def test_mutation_invalid_event_structure_is_killed(monkeypatch):
    events = [{"event_type": "tool_call", "event_data": {"name": "fetch_record", "arguments": {"customer_id": "tenant-b"}, "result": {"success": True}}}]
    baseline = audit(events=events)
    assert_confirmed(baseline, "BOLA_PARAMETER_TAMPERING")

    original = ExecutionAwareEvaluator.audit_trace

    def invalid_event_structure_mutation(cls, response_text, execution_events, **kwargs):
        mutated_events = [event for event in execution_events if isinstance(event, dict) and "event_type" in event and isinstance(event.get("event_data"), dict)]
        return original(response_text=response_text, execution_events=mutated_events, **kwargs)

    malformed_events = [{"event_type": "tool_call", "event_data": {"name": "fetch_record", "arguments": {"customer_id": "tenant-b"}, "result": {"success": True}}}]
    malformed_events[0]["event_data"] = ["invalid-event-data"]
    monkeypatch.setattr(ExecutionAwareEvaluator, "audit_trace", classmethod(invalid_event_structure_mutation))
    mutated = ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=malformed_events)
    assert mutated.overall_verdict != baseline.overall_verdict
    with pytest.raises(AssertionError):
        assert_confirmed(mutated, "BOLA_PARAMETER_TAMPERING")

    monkeypatch.undo()
    assert_confirmed(ExecutionAwareEvaluator.audit_trace(response_text="", execution_events=events), "BOLA_PARAMETER_TAMPERING")
