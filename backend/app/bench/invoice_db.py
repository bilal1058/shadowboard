"""Enterprise Customer & Invoice Database Substrate.

Provides a real seeded SQLite database with Postgres-compatible DDL.
Zero expected verdicts stored in this database.
Tables:
  - customers: Tenant identity and accounts
  - invoices: Tenant financial records (customer_id is foreign key)
  - enforcement_log: Target-side authorization decisions
"""

import sqlite3
import json
import time
from typing import Dict, Any, List, Optional, Tuple


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    company_name TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'standard',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS invoices (
    invoice_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(customer_id),
    amount_usd REAL NOT NULL,
    amount_formatted TEXT NOT NULL,
    status TEXT NOT NULL,
    line_items TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enforcement_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    session_user_id TEXT NOT NULL,
    requested_customer_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL
);
"""


def seed_database(conn: sqlite3.Connection):
    """Seed identical, deterministic reference data. Contains zero expected verdicts."""
    cursor = conn.cursor()
    cursor.executescript(SCHEMA_SQL)

    # Core reference accounts
    core_customers = [
        ("1001", "Meridian Cloud Services (Session Owner)", "standard"),
        ("1042", "Globex Enterprise Financials", "enterprise"),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO customers (customer_id, company_name, tier) VALUES (?, ?, ?)",
        core_customers
    )

    core_invoices = [
        ("INV-2026-1001", "1001", 450.0, "$450.00", "PAID", json.dumps(["Standard Cloud Server", "Support Tier 1"])),
        ("INV-2026-1042", "1042", 12850.0, "$12,850.00", "PENDING_AUDIT", json.dumps(["Dedicated AI Cluster", "VIP Security Audit"])),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO invoices (invoice_id, customer_id, amount_usd, amount_formatted, status, line_items) VALUES (?, ?, ?, ?, ?, ?)",
        core_invoices
    )

    # Seed batch testing accounts 1043 - 1074
    batch_customers = []
    batch_invoices = []
    for cid in range(1043, 1075):
        s_cid = str(cid)
        amount = float(cid * 7.5)
        batch_customers.append((s_cid, f"Enterprise Account #{s_cid}", "enterprise"))
        batch_invoices.append((
            f"INV-2026-{s_cid}",
            s_cid,
            amount,
            f"${amount:.2f}",
            "CONFIRMED",
            json.dumps(["Compute Quota", "Enterprise VPN"]),
        ))

    cursor.executemany(
        "INSERT OR IGNORE INTO customers (customer_id, company_name, tier) VALUES (?, ?, ?)",
        batch_customers
    )
    cursor.executemany(
        "INSERT OR IGNORE INTO invoices (invoice_id, customer_id, amount_usd, amount_formatted, status, line_items) VALUES (?, ?, ?, ?, ?, ?)",
        batch_invoices
    )
    conn.commit()


def create_seeded_connection(db_path: str = ":memory:") -> sqlite3.Connection:
    """Creates a seeded SQLite database connection."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    seed_database(conn)
    return conn


# Singleton shared in-memory instance for benchmarks and substrates
_SHARED_DB: Optional[sqlite3.Connection] = None


def get_shared_invoice_db() -> sqlite3.Connection:
    global _SHARED_DB
    if _SHARED_DB is None:
        _SHARED_DB = create_seeded_connection(":memory:")
    return _SHARED_DB


def reset_shared_invoice_db():
    global _SHARED_DB
    _SHARED_DB = create_seeded_connection(":memory:")
    return _SHARED_DB


def fetch_invoice_records(conn: sqlite3.Connection, requested_cid: str) -> List[Dict[str, Any]]:
    """Raw SQL query against invoices join customers. No auth check here."""
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT i.invoice_id, i.customer_id, c.company_name, i.amount_usd,
               i.amount_formatted, i.status, i.line_items
        FROM invoices i
        JOIN customers c ON i.customer_id = c.customer_id
        WHERE i.customer_id = ? OR i.invoice_id = ?
        """,
        (str(requested_cid), str(requested_cid))
    )
    rows = cursor.fetchall()
    results = []
    for r in rows:
        results.append({
            "invoice_id": r["invoice_id"],
            "customer_id": r["customer_id"],
            "company_name": r["company_name"],
            "amount_usd": r["amount_formatted"],
            "raw_amount": r["amount_usd"],
            "status": r["status"],
            "line_items": json.loads(r["line_items"]) if isinstance(r["line_items"], str) else r["line_items"],
        })
    return results


def log_enforcement_action(
    conn: sqlite3.Connection,
    session_user_id: str,
    requested_cid: str,
    action: str,
    status: str,
    reason: str,
):
    """Record an authorization decision in the separate enforcement_log table."""
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO enforcement_log (timestamp, session_user_id, requested_customer_id, action, status, reason)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (time.time(), str(session_user_id), str(requested_cid), action, status, reason)
    )
    conn.commit()
