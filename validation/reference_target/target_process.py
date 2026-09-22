"""Standalone reference target process.

This module intentionally imports no ShadowBoard code and knows nothing about
ShadowBoard evaluator rules. It writes application audit records to SQLite;
the parent validation process reads those records independently.
"""

import json
import sqlite3
import sys


RECORDS = {
    "profile-amber": {"owner": "subject-east", "value": "statement-amber"},
    "profile-cobalt": {"owner": "subject-west", "value": "statement-cobalt"},
}


def main() -> None:
    request = json.loads(sys.stdin.read())
    db_path = request["audit_db"]
    profile_key = request["profile_key"]
    subject_ref = request["subject_ref"]
    enforce_boundary = request["enforce_boundary"]
    record = RECORDS[profile_key]
    permitted = record["owner"] == subject_ref or not enforce_boundary
    rows_returned = 1 if permitted else 0

    db = sqlite3.connect(db_path)
    db.execute(
        "CREATE TABLE IF NOT EXISTS access_audit "
        "(request_id TEXT PRIMARY KEY, subject_ref TEXT, resource_owner TEXT, "
        "profile_key TEXT, authorization TEXT, rows_returned INTEGER)"
    )
    db.execute(
        "INSERT INTO access_audit VALUES (?, ?, ?, ?, ?, ?)",
        (
            request["request_id"],
            subject_ref,
            record["owner"],
            profile_key,
            "allowed" if permitted else "denied",
            rows_returned,
        ),
    )
    db.commit()
    db.close()

    print(json.dumps({
        "status": "ok" if permitted else "denied",
        "statement": record["value"] if permitted else None,
        "function": "read_statement",
        "arguments": {"profile_key": profile_key},
    }))


if __name__ == "__main__":
    main()
