"""Independent Ground Truth Package for ShadowBoard."""

from app.groundtruth.evaluator import (
    GroundTruthResult,
    UnifiedGroundTruthOracle,
    ground_truth_oracle,
)

__all__ = [
    "GroundTruthResult",
    "UnifiedGroundTruthOracle",
    "ground_truth_oracle",
]
