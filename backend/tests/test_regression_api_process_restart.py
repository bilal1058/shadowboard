"""End-to-end regression API persistence across real process boundaries."""

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def _run_process(code: str, db_path: Path) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND) + os.pathsep + env.get("PYTHONPATH", "")
    env["SHADOWBOARD_DB_PATH"] = str(db_path)
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(BACKEND),
            env=env,
            check=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.CalledProcessError as e:
        print("CHILD STDERR:", (e.stderr or "").encode("ascii", errors="replace").decode("ascii"))
        print("CHILD STDOUT:", (e.stdout or "").encode("ascii", errors="replace").decode("ascii"))
        raise
    for line in reversed(result.stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                if "status" in data or "baseline_status" in data:
                    return data
            except json.JSONDecodeError:
                continue
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_regression_api_baseline_survives_process_restart(tmp_path):
    db_path = tmp_path / "api-regression.sqlite3"

    writer = _run_process(
        """
import json
import sqlite3
from fastapi.testclient import TestClient
from main import app
from app.db.session import DB_PATH

with TestClient(app) as client:
    db = sqlite3.connect(DB_PATH)
    db.execute("INSERT INTO scan_runs (id, target_id, status, overall_score, risk_grade) VALUES (901, 2, 'COMPLETED', 100, 'A')")
    db.commit()
    db.close()
    response = client.post('/api/regression/baseline', json={'target_id': 2, 'scan_id': 901})
    print(json.dumps({'status': response.status_code, 'target_id': response.json().get('target_id'), 'scan_id': response.json().get('scan_id')}))
""",
        db_path,
    )
    assert writer == {"status": 200, "target_id": 2, "scan_id": 901}

    reader = _run_process(
        """
import json
from fastapi.testclient import TestClient
from main import app

with TestClient(app) as client:
    baseline = client.get('/api/regression/baseline/2')
    diff = client.post('/api/regression/diff', json={'target_id': 2, 'current_scan_id': 901})
    print(json.dumps({
        'baseline_status': baseline.status_code,
        'baseline_scan_id': baseline.json().get('scan_id'),
        'diff_status': diff.status_code,
        'diff_gate': diff.json().get('ci_gate_status'),
        'diff_current_scan_id': diff.json().get('current_scan_id'),
    }))
""",
        db_path,
    )
    assert reader == {
        "baseline_status": 200,
        "baseline_scan_id": 901,
        "diff_status": 200,
        "diff_gate": "PASSED",
        "diff_current_scan_id": 901,
    }
