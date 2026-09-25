"""Short-lived, HttpOnly administrative browser sessions.

The session key is derived from the server-only administrator key. Rotating the
administrator key invalidates every browser session automatically.
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

COOKIE_NAME = "sb_admin_session"


def _fernet() -> Fernet:
    admin_key = settings.admin_key
    if not admin_key:
        raise RuntimeError("SHADOWBOARD_ADMIN_KEY is not configured")
    material = hashlib.sha256(f"shadowboard-session:{admin_key}".encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(material))


def issue_admin_session() -> str:
    return _fernet().encrypt(b"shadowboard-admin-v1").decode("ascii")


def is_valid_admin_session(token: str | None) -> bool:
    if not token or not settings.admin_key:
        return False
    try:
        return _fernet().decrypt(token.encode("ascii"), ttl=settings.ADMIN_SESSION_TTL_SECONDS) == b"shadowboard-admin-v1"
    except (InvalidToken, ValueError, TypeError):
        return False
