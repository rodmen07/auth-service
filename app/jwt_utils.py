import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException

from app.models import JwtConfig

APP_TITLE = "auth-service"

_DEFAULT_SECRET = "dev-insecure-secret-change-me"

logger = logging.getLogger(__name__)


def get_jwt_config() -> JwtConfig:
    secret = os.getenv("AUTH_JWT_SECRET", _DEFAULT_SECRET)
    algorithm = os.getenv("AUTH_JWT_ALGORITHM", "HS256")
    expires_seconds_raw = os.getenv("AUTH_TOKEN_EXPIRES_SECONDS", "3600")
    issuer = os.getenv("AUTH_ISSUER", APP_TITLE)

    if secret == _DEFAULT_SECRET:
        logger.warning(
            "AUTH_JWT_SECRET is using the default insecure value. "
            "Set AUTH_JWT_SECRET to a strong random secret in production."
        )

    if len(secret) < 32:
        logger.warning(
            "AUTH_JWT_SECRET is shorter than 32 characters. "
            "Use a secret with at least 32 characters for adequate security."
        )

    try:
        expires_seconds = int(expires_seconds_raw)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="Invalid AUTH_TOKEN_EXPIRES_SECONDS") from exc

    if expires_seconds <= 0:
        raise HTTPException(status_code=500, detail="AUTH_TOKEN_EXPIRES_SECONDS must be positive")

    return JwtConfig(
        secret=secret,
        algorithm=algorithm,
        expires_seconds=expires_seconds,
        issuer=issuer,
    )


def build_access_token(*, subject: str, roles: list[str], config: JwtConfig) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=config.expires_seconds)

    payload: dict[str, Any] = {
        "sub": subject,
        "roles": roles,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": config.issuer,
    }

    token = jwt.encode(payload, config.secret, algorithm=config.algorithm)
    return token, config.expires_seconds


def decode_access_token(token: str, config: JwtConfig) -> dict[str, Any]:
    return jwt.decode(
        token,
        config.secret,
        algorithms=[config.algorithm],
        options={"require": ["sub", "exp", "iat", "iss"]},
    )
