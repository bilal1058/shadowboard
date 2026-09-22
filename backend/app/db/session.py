"""Database session manager with dual support: SQLite (default) and PostgreSQL."""
import os
from pathlib import Path
from typing import AsyncGenerator
import aiosqlite
from loguru import logger
from app.core.config import settings

DB_PATH = Path(os.getenv("SHADOWBOARD_DB_PATH", str(Path(__file__).parent.parent.parent / "shadowboard.db")))
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

_pool = None
DB_URL = os.getenv("DATABASE_URL", "postgresql://shadowboard:shadowboard@localhost:5432/shadowboard")


async def get_pool():
    global _pool
    if not settings.USE_POSTGRES:
        return None
    try:
        import asyncpg
        if _pool is None or _pool._closed:
            _pool = await asyncpg.create_pool(
                dsn=DB_URL,
                min_size=5,
                max_size=20,
                command_timeout=30,
                max_inactive_connection_lifetime=300,
            )
            logger.info("PostgreSQL pool created")
        return _pool
    except ImportError:
        logger.warning("asyncpg not installed; falling back to SQLite")
        return None


async def get_db():
    if settings.USE_POSTGRES:
        pool = await get_pool()
        if pool:
            async with pool.acquire() as conn:
                await conn.set_type_codec("json", encoder=str, decoder=lambda x: x, schema="pg_catalog")
                await conn.set_type_codec("jsonb", encoder=str, decoder=lambda x: x, schema="pg_catalog")
                yield conn
                return

    # Default SQLite / aiosqlite
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA foreign_keys=ON;")
        cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='targets';")
        if not await cursor.fetchone():
            with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                schema_sql = f.read()
            await db.executescript(schema_sql)
            await _seed_default_targets(db)
            await db.commit()
        yield db


async def _seed_default_targets(db):
    import json
    from app.api.endpoints.policies import default_policy_for_target_type
    reference_targets = [
        {
            "name": "Meridian Support Assistant",
            "base_url": os.getenv("TARGET_APP_URL", "http://127.0.0.1:8000/target-app"),
            "target_type": "EXTERNAL_SUPPORT",
            "capabilities": {"chat": True, "rag": False, "tools": False, "data_access": False, "has_rag": False, "has_tools": False, "has_memory": False, "tool_names": []},
        },
        {
            "name": "Meridian Internal Knowledge Assistant",
            "base_url": "http://127.0.0.1:8000/internal-rag",
            "target_type": "INTERNAL_RAG",
            "capabilities": {"chat": True, "rag": True, "tools": True, "data_access": True, "has_rag": True, "has_tools": True, "has_memory": False, "tool_names": ["get_invoice", "send_email"]},
        },
    ]
    for target in reference_targets:
        cursor = await db.execute("SELECT id FROM targets WHERE base_url = ?", (target["base_url"],))
        row = await cursor.fetchone()
        if not row:
            cursor = await db.execute(
                "INSERT INTO targets (name, base_url, model_name, target_type, target_mode, capabilities_json) VALUES (?, ?, ?, ?, ?, ?)",
                (target["name"], target["base_url"], "qwen-flash", target["target_type"], "INSTRUMENTED", json.dumps(target["capabilities"])),
            )
            target_id = cursor.lastrowid
            await db.execute(
                "INSERT INTO policies (target_id, policy_json, taxonomy, taxonomy_version) VALUES (?, ?, ?, ?)",
                (target_id, json.dumps(default_policy_for_target_type(target["target_type"])), "OWASP", "2025"),
            )
    cursor = await db.execute("SELECT COUNT(*) FROM scan_runs;")
    if (await cursor.fetchone())[0] == 0:
        await db.execute(
            "INSERT INTO scan_runs (id, target_id, status, overall_score, risk_grade, started_at, completed_at) "
            "VALUES (1, 1, 'COMPLETED', 85, 'B', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
        await db.execute(
            "INSERT INTO scan_runs (id, target_id, status, overall_score, risk_grade, started_at, completed_at) "
            "VALUES (2, 2, 'COMPLETED', 75, 'C', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
        await db.execute(
            "INSERT INTO findings (scan_id, finding_id, owasp_category, status, attack_outcome, evidence_status, confidence, severity, evidence_json, evidence_hash, remediation) "
            "VALUES (1, 'FND-INIT-001', 'LLM01', 'PASS', 'BLOCKED', 'SUFFICIENT', 0.90, 'LOW', '{}', 'hash001', 'Maintain system prompt boundaries.')"
        )
        await db.execute(
            "INSERT INTO findings (scan_id, finding_id, owasp_category, status, attack_outcome, evidence_status, confidence, severity, evidence_json, evidence_hash, remediation) "
            "VALUES (2, 'FND-INIT-002', 'LLM02', 'CONFIRMED', 'COMPLIED', 'SUFFICIENT', 0.95, 'HIGH', '{}', 'hash002', 'Enforce tenant isolation on tool calls.')"
        )
    await db.commit()


async def init_db():
    """Initialize database schema."""
    if settings.USE_POSTGRES:
        pool = await get_pool()
        if pool:
            async with pool.acquire() as conn:
                with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                    schema_sql = f.read()
                for statement in schema_sql.split(";"):
                    statement = statement.strip()
                    if statement and not statement.startswith("PRAGMA"):
                        try:
                            await conn.execute(statement)
                        except Exception as e:
                            logger.debug("Schema statement skipped: {}", str(e)[:100])
                logger.info("PostgreSQL database schema initialized")
                return

    # Default SQLite initialization
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA foreign_keys=ON;")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_sql = f.read()
        await db.executescript(schema_sql)
        await _seed_default_targets(db)
        await db.commit()
    logger.info("SQLite database schema initialized at {}", DB_PATH)


async def close_db():
    """Close the database pool if Postgres is active."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("PostgreSQL pool closed")


def get_db_sync():
    """Return DB connection string."""
    return DB_URL

