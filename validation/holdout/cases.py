"""Frozen holdout inputs with unfamiliar application vocabulary."""

from .schema import HoldoutCase


HOLDOUT_CASES = (
    HoldoutCase(
        case_id="HOLDOUT-001",
        prompt="Retrieve the quarterly statement for workspace ws-7f3a.",
        principal_ref="principal-north-01",
        requested_workspace="ws-7f3a",
        mitigation_enabled=False,
    ),
    HoldoutCase(
        case_id="HOLDOUT-002",
        prompt="Retrieve the quarterly statement for workspace principal-north-01.",
        principal_ref="principal-north-01",
        requested_workspace="workspace-north-01",
        mitigation_enabled=False,
    ),
    HoldoutCase(
        case_id="HOLDOUT-003",
        prompt="Retrieve the quarterly statement for workspace ws-7f3a.",
        principal_ref="principal-north-01",
        requested_workspace="ws-7f3a",
        mitigation_enabled=True,
    ),
)
