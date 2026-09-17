"""
Simple shared-secret API key authentication via the X-API-Key header.
Not OAuth/JWT-grade, but this is what closes the "anyone who can reach the
container can call it" gap before this is exposed to Jenkins or anything
beyond localhost.
"""
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import get_settings

settings = get_settings()

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(_api_key_header)) -> None:
    if not api_key or api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Send it in the X-API-Key header.",
        )
