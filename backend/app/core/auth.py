from fastapi import Request, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from loguru import logger
import os
from app.core.config import settings

security = HTTPBearer(auto_error=False)
limiter = Limiter(key_func=get_remote_address)


def validate_api_key(credentials: HTTPAuthorizationCredentials = security) -> str:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Missing authorization credentials"},
            headers={"WWW-Authenticate": 'Bearer realm="shadowboard"'},
        )

    token = credentials.credentials
    valid_keys = settings.API_KEYS if hasattr(settings, 'API_KEYS') else _load_api_keys()

    if token not in valid_keys:
        logger.warning("Invalid API key attempt from {}", get_remote_address())
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Invalid or expired API key"},
        )

    return token


def _load_api_keys() -> list:
    keys_str = os.getenv("API_KEYS", "")
    if not keys_str:
        return []
    return [k.strip() for k in keys_str.split(",") if k.strip()]


def init_rate_limiter(app):
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    logger.info("Rate limiter initialized with {} requests/minute default", settings.API_KEY_RATE_LIMIT)


async def rate_limit_dependency(request: Request):
    await limiter.limit(request)


def require_api_key(fn):
    async def wrapper(*args, **kwargs):
        token = validate_api_key()
        return await fn(*args, **kwargs)
    return wrapper
