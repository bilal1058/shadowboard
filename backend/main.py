import os
import sys
import json
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.core.middleware import init_security_middleware
from app.core.auth import init_rate_limiter
from app.db.session import init_db, get_db
from app.api.router import api_router
from app.target_app.app import app as target_app, support_ui
from app.internal_rag.app import app as internal_rag_app, internal_rag_ui

# Optional: Sentry
sentry_initialized = False
if settings.SENTRY_DSN:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration
        sentry_logging = LoggingIntegration(level=logging.INFO, event_level=logging.WARNING)
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            integrations=[FastApiIntegration(), sentry_logging],
            traces_sample_rate=0.1,
            environment=settings.SENTRY_ENVIRONMENT or settings.APP_ENV,
        )
        sentry_initialized = True
        logger.info("Sentry initialized")
    except ImportError:
        logger.warning("Sentry SDK not available")

# Initialize logging
setup_logging(level=settings.LOG_LEVEL, format=settings.LOG_FORMAT, destination=settings.LOG_DESTINATION)
logger.info("ShadowBoard starting", env=settings.APP_ENV, version=settings.APP_VERSION)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting ShadowBoard lifespan")

    # Initialize DB
    await init_db()
    logger.info("Database initialized")

    # Register reference targets
    import aiosqlite
    from app.db.session import DB_PATH
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute("PRAGMA foreign_keys=ON;")
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
                if row:
                    target_id = row[0]
                    await db.execute(
                        "UPDATE targets SET name = ?, target_type = ?, capabilities_json = ? WHERE id = ?",
                        (target["name"], target["target_type"], json.dumps(target["capabilities"]), target_id),
                    )
                    policy_dict = default_policy_for_target_type(target["target_type"])
                    cursor = await db.execute("SELECT COUNT(*) FROM policies WHERE target_id = ?", (target_id,))
                    if (await cursor.fetchone())[0] == 0:
                        await db.execute(
                            "INSERT INTO policies (target_id, policy_json, taxonomy, taxonomy_version) VALUES (?, ?, ?, ?)",
                            (target_id, json.dumps(policy_dict), "OWASP", "2025"),
                        )
                    else:
                        await db.execute(
                            "UPDATE policies SET policy_json = ?, taxonomy = ?, taxonomy_version = ? WHERE target_id = ?",
                            (json.dumps(policy_dict), "OWASP", "2025", target_id),
                        )
                else:
                    cursor = await db.execute(
                        "INSERT INTO targets (name, base_url, model_name, target_type, target_mode, capabilities_json) VALUES (?, ?, ?, ?, ?, ?)",
                        (target["name"], target["base_url"], "qwen-flash", target["target_type"], "INSTRUMENTED", json.dumps(target["capabilities"])),
                    )
                    target_id = cursor.lastrowid
                    await db.execute(
                        "INSERT INTO policies (target_id, policy_json, taxonomy, taxonomy_version) VALUES (?, ?, ?, ?)",
                        (target_id, json.dumps(default_policy_for_target_type(target["target_type"])), "OWASP", "2025"),
                    )
            await db.commit()
            logger.info("Reference targets registered")
        except Exception as e:
            logger.warning("Could not register reference targets: {}", e)

    # Initialize rate limiter
    init_rate_limiter(app)

    logger.info("ShadowBoard lifespan complete")
    yield

    logger.info("ShadowBoard shutting down")


# Build FastAPI app
app = FastAPI(
    title="ShadowBoard — AI Security Assurance Platform",
    description="Executable security policy evaluation with trace-driven evidence verification. Production-ready.",
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# Security middleware
cors_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")]
init_security_middleware(app, cors_origins)

# Health endpoints
@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
async def health():
    return {
        "status": "healthy",
        "service": "shadowboard",
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "database": "sqlite",
    }


@app.get("/ready", tags=["Health"])
async def ready():
    try:
        await init_db()
        return {"status": "ready"}
    except Exception as e:
        return Response(status_code=503, content=f'{{"status": "not ready", "error": "{str(e)}"}}', media_type="application/json")

@app.get("/live", tags=["Health"])
async def live():
    return {"status": "alive"}

# Metrics endpoint (Prometheus)
if settings.ENABLE_METRICS:
    try:
        from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
        REQUEST_COUNT = Counter('shadowboard_http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
        REQUEST_LATENCY = Histogram('shadowboard_http_request_duration_seconds', 'HTTP request latency', ['method', 'endpoint'])
        SCAN_COUNT = Counter('shadowboard_scans_total', 'Total scans executed', ['target_id', 'mitigation_enabled'])
        FINDINGS_COUNT = Counter('shadowboard_findings_total', 'Total findings', ['severity'])

        @app.get("/metrics", include_in_schema=False, tags=["Monitoring"])
        async def metrics():
            return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
        logger.info("Prometheus metrics enabled")
    except ImportError:
        logger.warning("prometheus-client not available, metrics disabled")

# Mount API
app.include_router(api_router)

# Mount sub-apps
app.mount("/target-app", target_app)
app.mount("/internal-rag", internal_rag_app)

# Serve frontend
root_frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
backend_static_dir = os.path.join(os.path.dirname(__file__), "static")
frontend_static_dir = root_frontend_dir if os.path.exists(root_frontend_dir) else backend_static_dir

# Mount Vite assets directory (/assets/index-*.js, /assets/index-*.css)
assets_dir = os.path.join(frontend_static_dir, "assets")
if os.path.exists(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

# Mount static directory for general static files
if os.path.exists(frontend_static_dir):
    app.mount("/static", StaticFiles(directory=frontend_static_dir), name="static")

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    svg_icon = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#dc2626"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5zm0 2.18l7 3.89v4.93c0 4.54-3.14 8.79-7 9.94-3.86-1.15-7-5.4-7-9.94V8.07l7-3.89z"/></svg>"""
    return Response(content=svg_icon, media_type="image/svg+xml")

@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str = ""):
    # If a specific static file exists directly in frontend_static_dir, serve it
    file_path = os.path.join(frontend_static_dir, full_path)
    if full_path and os.path.isfile(file_path):
        return FileResponse(file_path)
    # SPA catch-all: serve index.html for client-side routing
    index_file = os.path.join(frontend_static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse(content="<h1>ShadowBoard Security Engine Active</h1><p>API docs at <a href='/docs'>/docs</a></p>")

if __name__ == "__main__":
    if not os.getenv("SHADOWBOARD_ADMIN_KEY") and not os.getenv("SHADOWBOARD_API_KEY"):
        os.environ["SHADOWBOARD_ADMIN_KEY"] = "shadowboard_admin_secret_2026"
        logger.info("SHADOWBOARD_ADMIN_KEY defaulted to 'shadowboard_admin_secret_2026' for local development")
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS,
        log_level=settings.LOG_LEVEL.lower(),
        reload=False,
        access_log=True,
    )
