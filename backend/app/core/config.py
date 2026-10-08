import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import Optional, List

# Search and load environment variables into os.environ (outside pytest)
_is_test = "pytest" in sys.modules or os.getenv("APP_ENV") == "test" or "PYTEST_CURRENT_TEST" in os.environ
if not _is_test:
    _root_dir = Path(__file__).resolve().parent.parent.parent.parent
    _backend_dir = Path(__file__).resolve().parent.parent.parent
    for _env_file in [_root_dir / ".env", _backend_dir / ".env", Path(".env"), Path("backend/.env")]:
        if _env_file.exists():
            load_dotenv(_env_file, override=False)




class Settings(BaseSettings):
    APP_ENV: str = "development"
    APP_NAME: str = "ShadowBoard"
    APP_VERSION: str = "1.0.0"

    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = Field(default=4, ge=1, le=32)

    DATABASE_URL: str = Field(default="sqlite:///backend/shadowboard.db", alias="DATABASE_URL")
    USE_POSTGRES: bool = False

    # Central fail-closed administrative API key
    SHADOWBOARD_ADMIN_KEY: Optional[str] = None
    SHADOWBOARD_API_KEY: Optional[str] = None
    ADMIN_SESSION_TTL_SECONDS: int = Field(default=1800, ge=300, le=28800)
    TARGET_CONTROL_KEY: Optional[str] = None

    # Model providers
    TARGET_MODEL: str = "qwen-flash"
    GROQ_API_KEY: Optional[str] = None
    OPENROUTER_API_KEY: Optional[str] = None
    DASHSCOPE_API_KEY: Optional[str] = None

    # Evidence Signing
    SIGNING_KEY_PATH: Optional[str] = None
    KEY_ID: Optional[str] = None

    # Rate limiting
    API_KEYS: Optional[str] = None
    API_KEY_RATE_LIMIT: str = Field(default="20/minute")
    API_KEY_BURST: int = Field(default=5, ge=1)

    # CORS
    CORS_ORIGINS: str = Field(default="http://localhost:3000,http://localhost:8000,http://127.0.0.1:3000,http://127.0.0.1:8000")
    SENTRY_DSN: Optional[str] = None
    SENTRY_ENVIRONMENT: Optional[str] = None

    LOG_LEVEL: str = "info"
    LOG_FORMAT: str = "json"
    LOG_DESTINATION: str = "stdout"

    ENABLE_METRICS: bool = False
    METRICS_PORT: int = 9090

    DEFAULT_TARGET_URL: Optional[str] = None
    SCAN_TIMEOUT_SECONDS: int = Field(default=300, ge=30, le=3600)
    SSE_HEARTBEAT_INTERVAL: int = Field(default=15, ge=5, le=60)

    @property
    def admin_key(self) -> Optional[str]:
        return self.SHADOWBOARD_ADMIN_KEY or self.SHADOWBOARD_API_KEY

    @field_validator("API_KEYS")
    @classmethod
    def parse_api_keys(cls, v):
        if v:
            return [k.strip() for k in v.split(",") if k.strip()]
        return []

    @field_validator("CORS_ORIGINS")
    @classmethod
    def parse_cors(cls, v):
        if not v:
            return ["http://127.0.0.1:8000"]
        origins = [origin.strip() for origin in v.split(",") if origin.strip()]
        for origin in origins:
            if origin == "*":
                raise ValueError("Wildcard CORS origin '*' is strictly prohibited.")
        return origins

    model_config = {
        "env_file": None if ("pytest" in sys.modules or os.getenv("APP_ENV") == "test" or "PYTEST_CURRENT_TEST" in os.environ) else (".env" if os.path.exists(".env") else ("backend/.env" if os.path.exists("backend/.env") else None)),
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


settings = Settings()

if not _is_test:
    if settings.GROQ_API_KEY and not os.environ.get("GROQ_API_KEY"):
        os.environ["GROQ_API_KEY"] = settings.GROQ_API_KEY
    if settings.OPENROUTER_API_KEY and not os.environ.get("OPENROUTER_API_KEY"):
        os.environ["OPENROUTER_API_KEY"] = settings.OPENROUTER_API_KEY


