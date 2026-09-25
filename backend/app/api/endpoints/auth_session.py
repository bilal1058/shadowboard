"""Browser-session bootstrap for the administrative console."""

import secrets

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.core.admin_session import COOKIE_NAME, issue_admin_session
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("Authorization", "")
    return header[7:].strip() if header.startswith("Bearer ") else None


@router.post("/session", status_code=status.HTTP_204_NO_CONTENT)
async def establish_session(request: Request, response: Response) -> Response:
    """Exchange an administrator key for a short-lived HttpOnly same-site cookie."""
    admin_key = settings.admin_key
    token = _bearer_token(request)
    if not admin_key or not token or not secrets.compare_digest(token.encode(), admin_key.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid administrative credentials.")

    response.status_code = status.HTTP_204_NO_CONTENT
    response.set_cookie(
        key=COOKIE_NAME,
        value=issue_admin_session(),
        max_age=settings.ADMIN_SESSION_TTL_SECONDS,
        httponly=True,
        secure=settings.APP_ENV.lower() in {"production", "staging"},
        samesite="strict",
        path="/api",
    )
    return response


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
async def destroy_session(response: Response) -> Response:
    response.delete_cookie(key=COOKIE_NAME, path="/api", httponly=True, samesite="strict")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
