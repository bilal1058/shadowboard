"""Process-boundary verification for persistent regression baselines."""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
SCHEMA = BACKEND / "app" / "db" / "schema.sql"


def _run_process(code: str, db_path: Path) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND)
    result = subprocess.run(
        [sys.executable, "-c", code, str(db_path)],
        cwd=str(ROOT),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_regression_baseline_survives_fresh_process_and_is_target_scoped(tmp_path):
    db_path = tmp_path / "regression-persistence.sqlite3"
    schema_sql = SCHEMA.read_text(encoding="utf-8")
    db = sqlite3.connect(db_path)
    db.executescript(schema_sql)
    db.execute("INSERT INTO targets (id, name, base_url, model_name, capabilities_json) VALUES (1, 'A', 'http://a', 'test', '{}')")
    db.execute("INSERT INTO targets (id, name, base_url, model_name, capabilities_json) VALUES (2, 'B', 'http://b', 'test', '{}')")
    db.execute("INSERT INTO scan_runs (id, target_id, status, overall_score, risk_grade) VALUES (101, 1, 'COMPLETED', 40, 'F')")
    db.execute("INSERT INTO scan_runs (id, target_id, status, overall_score, risk_grade) VALUES (202, 2, 'COMPLETED', 90, 'A')")
    db.commit()
    db.close()

    writer = _run_process(
        """
import json, sqlite3, sys
from app.regression.regression_engine import ContinuousRegressionEngine
path = sys.argv[1]
findings = [{'finding_id': 'generated-a', 'status': 'CONFIRMED', 'severity': 'CRITICAL', 'security_property': 'owner_scoped_read'}]
baseline = ContinuousRegressionEngine.create_baseline(1, 101, 40, 'F', findings)
db = sqlite3.connect(path)
db.execute('INSERT INTO security_baselines (target_id, scan_id, baseline_json) VALUES (?, ?, ?)', (1, 101, json.dumps(baseline.model_dump())))
findings_b = [{'finding_id': 'generated-b', 'status': 'CONFIRMED', 'severity': 'HIGH', 'security_property': 'unauthorized_network_egress'}]
baseline_b = ContinuousRegressionEngine.create_baseline(2, 202, 90, 'A', findings_b)
db.execute('INSERT INTO security_baselines (target_id, scan_id, baseline_json) VALUES (?, ?, ?)', (2, 202, json.dumps(baseline_b.model_dump())))
db.commit()
db.close()
print(json.dumps({'stored': True}))
""",
        db_path,
    )
    assert writer == {"stored": True}

    reader = _run_process(
        """
import json, sqlite3, sys
from app.regression.regression_engine import ContinuousRegressionEngine, SecurityBaseline
path = sys.argv[1]
db = sqlite3.connect(path)
rows = db.execute('SELECT target_id, baseline_json FROM security_baselines ORDER BY target_id').fetchall()
loaded = {target_id: SecurityBaseline(**json.loads(payload)) for target_id, payload in rows}
comparison_a = ContinuousRegressionEngine.compare_against_baseline(
    loaded[1], 102, 100, 'A',
    [{'finding_id': 'new-id', 'status': 'PASS', 'severity': 'CRITICAL', 'security_property': 'owner_scoped_read'}],
)
comparison_b = ContinuousRegressionEngine.compare_against_baseline(
    loaded[2], 203, 100, 'A',
    [{'finding_id': 'new-id', 'status': 'PASS', 'severity': 'HIGH', 'security_property': 'unauthorized_network_egress'}],
)
print(json.dumps({
    'target_ids': sorted(loaded),
    'scan_ids': {str(k): v.scan_id for k, v in loaded.items()},
    'a_resolved': len(comparison_a.resolved_vulnerabilities),
    'b_resolved': len(comparison_b.resolved_vulnerabilities),
}))
""",
        db_path,
    )

    assert reader == {
        "target_ids": [1, 2],
        "scan_ids": {"1": 101, "2": 202},
        "a_resolved": 1,
        "b_resolved": 1,
    }

    db = sqlite3.connect(db_path)
    assert db.execute("SELECT scan_id FROM security_baselines WHERE target_id = 1").fetchone()[0] == 101
    assert db.execute("SELECT scan_id FROM security_baselines WHERE target_id = 2").fetchone()[0] == 202
    assert db.execute("SELECT COUNT(*) FROM security_baselines WHERE target_id = 1 AND scan_id = 202").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM security_baselines WHERE target_id = 2 AND scan_id = 101").fetchone()[0] == 0
    db.close()
