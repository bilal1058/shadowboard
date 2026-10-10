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
        try:
            await db.execute("ALTER TABLE scan_runs ADD COLUMN tenant_matrix_json TEXT DEFAULT '[]';")
            await db.commit()
        except Exception:
            pass
        try:
            await db.execute("CREATE VIEW IF NOT EXISTS scans AS SELECT * FROM scan_runs;")
            await db.execute("CREATE VIEW IF NOT EXISTS scan_results AS SELECT * FROM findings;")
            await db.commit()
        except Exception:
            pass
        yield db


async def _seed_default_targets(db):
    import json
    from app.api.endpoints.policies import default_policy_for_target_type
    reference_targets = [
        {
            "id": 2,
            "name": "Meridian Enterprise Assistant",
            "base_url": "http://127.0.0.1:8000/internal-rag",
            "target_type": "INTERNAL_RAG",
            "capabilities": {
                "chat": True,
                "rag": True,
                "tools": True,
                "data_access": True,
                "has_rag": True,
                "has_tools": True,
                "has_memory": False,
                "tool_names": ["get_invoice", "send_email"],
            },
        },
    ]
    for target in reference_targets:
        cursor = await db.execute("SELECT id FROM targets WHERE base_url = ? OR id = ?", (target["base_url"], target["id"]))
        row = await cursor.fetchone()
        if not row:
            cursor = await db.execute(
                "INSERT INTO targets (id, name, base_url, model_name, target_type, target_mode, capabilities_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (target["id"], target["name"], target["base_url"], "qwen-flash", target["target_type"], "INSTRUMENTED", json.dumps(target["capabilities"])),
            )
            target_id = target["id"]
            await db.execute(
                "INSERT INTO policies (target_id, policy_json, taxonomy, taxonomy_version) VALUES (?, ?, ?, ?)",
                (target_id, json.dumps(default_policy_for_target_type(target["target_type"])), "OWASP", "2025"),
            )
        else:
            target_id = row[0]
            await db.execute(
                "UPDATE targets SET name = ?, target_type = ?, capabilities_json = ? WHERE id = ?",
                (target["name"], target["target_type"], json.dumps(target["capabilities"]), target_id),
            )
        await db.execute(
            "INSERT INTO target_security_config (target_id, mitigation_enabled) VALUES (?, FALSE) "
            "ON CONFLICT(target_id) DO NOTHING",
            (target_id,),
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
