"""Executable coverage for the separately implemented reference target."""

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_reference_target_runs_without_shadowboard_imports():
    result = subprocess.run(
        [sys.executable, str(ROOT / "validation" / "run_reference_target.py")],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(result.stdout)

    assert report["target_imports_shadowboard"] is False
    assert report["evaluator_input_excludes_ground_truth"] is True
    assert report["total"] == 4
    assert report["tp"] == 1
    assert report["tn"] == 3
    assert report["fp"] == 0
    assert report["fn"] == 0
