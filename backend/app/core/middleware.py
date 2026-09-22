from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from loguru import logger
import time
import uuid
import os
import sys
import secrets
from app.core.config import settings

PUBLIC_API_PATHS = {
    "/api/health",
    "/health",
    "/ready",
    "/live",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/favicon.ico",
}


def is_test_environment() -> bool:
    if os.getenv("APP_ENV") == "test" or os.getenv("TESTING") == "1":
        return True
    if "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ:
        return True
    return False


class AdminAuthMiddleware(BaseHTTPMiddleware):
    """Central fail-closed administrative API authentication middleware.
    Enforces SHADOWBOARD_ADMIN_KEY via constant-time comparison on all /api routes
    except health, docs, and the target sub-apps.
    """
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow CORS preflight OPTIONS
        if request.method == "OPTIONS":
            return await call_next(request)

        # Allow target sub-apps' own endpoints and UIs
        if path.startswith("/target-app") or path.startswith("/internal-rag"):
            return await call_next(request)

        # Only enforce on /api routes
        if not path.startswith("/api"):
            return await call_next(request)

        # Exempt public endpoints
        if path in PUBLIC_API_PATHS:
            return await call_next(request)

        admin_key = os.getenv("SHADOWBOARD_ADMIN_KEY") or os.getenv("SHADOWBOARD_API_KEY") or settings.admin_key

        if not admin_key:
            # If unset in non-test environments: fail closed (refuse to serve /api)
            if not is_test_environment():
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"detail": "Server fail-closed: SHADOWBOARD_ADMIN_KEY is not configured."},
                )
            # In test environment when no admin key is configured, allow legacy test fixtures
            return await call_next(request)

        # Key is configured: inspect Authorization / X-API-Key headers
        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")

        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif auth_header:
            token = auth_header.strip()
        elif api_key_header:
            token = api_key_header.strip()

        if not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Missing administrative authorization credentials."},
                headers={"WWW-Authenticate": 'Bearer realm="shadowboard"'},
            )

        # Constant-time comparison
        if not secrets.compare_digest(token.encode("utf-8"), admin_key.encode("utf-8")):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Invalid administrative API key."},
            )

        return await call_next(request)


class ProductionHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.app = app

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Server"] = "ShadowBoard"
        response.headers["Cache-Control"] = "no-store"
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.app = app

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        start_time = time.time()

        logger.info(
            "Request started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )

        try:
            response = await call_next(request)
            duration = round((time.time() - start_time) * 1000, 2)
            logger.info(
                "Request completed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration,
            )
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception as e:
            duration = round((time.time() - start_time) * 1000, 2)
            logger.error(
                "Request failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                error=str(e),
                duration_ms=duration,
            )
            raise


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Unhandled exception", error=str(e), path=request.url.path)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "Internal server error"},
            )


def init_cors(app, allowed_origins: list):
    # Strictly prohibited: wildcard "*" with credentials
    filtered_origins = [o for o in allowed_origins if o != "*"]
    if not filtered_origins:
        filtered_origins = ["http://127.0.0.1:8000"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=filtered_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Total-Count", "Link"],
        max_age=3600,
    )
    logger.info("CORS initialized with origins: {}", filtered_origins)


def init_security_middleware(app, cors_origins: list):
    init_cors(app, cors_origins)
    app.add_middleware(AdminAuthMiddleware)
    app.add_middleware(ProductionHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(ErrorHandlingMiddleware)
    logger.info("Security middleware initialized")
