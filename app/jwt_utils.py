import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException

from app.models import JwtConfig

APP_TITLE = "auth-service"

_DEFAULT_SECRET = "dev-insecure-secret-change-me"

logger = logging.getLogger(__name__)

_RSA_ALGORITHMS = {"RS256", "RS384", "RS512"}


def _normalise_pem(raw: str) -> str:
    """Convert escaped newlines (common in env vars) to real newlines."""
    return raw.replace("\\n", "\n").strip()


def get_jwt_config() -> JwtConfig:
    algorithm = os.getenv("AUTH_JWT_ALGORITHM", "HS256").strip().upper()
    expires_seconds_raw = os.getenv("AUTH_TOKEN_EXPIRES_SECONDS", "3600")
    issuer = os.getenv("AUTH_ISSUER", APP_TITLE)

    try:
        expires_seconds = int(expires_seconds_raw)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="Invalid AUTH_TOKEN_EXPIRES_SECONDS") from exc

    if expires_seconds <= 0:
        raise HTTPException(status_code=500, detail="AUTH_TOKEN_EXPIRES_SECONDS must be positive")

    # Symmetric (HS*) key material
    secret = os.getenv("AUTH_JWT_SECRET", _DEFAULT_SECRET)

    if algorithm not in _RSA_ALGORITHMS:
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

    # Asymmetric (RS*) key material
    private_key: str | None = None
    public_key: str | None = None

    if algorithm in _RSA_ALGORITHMS:
        raw_priv = os.getenv("AUTH_JWT_PRIVATE_KEY", "")
        raw_pub = os.getenv("AUTH_JWT_PUBLIC_KEY", "")
        if raw_priv:
            private_key = _normalise_pem(raw_priv)
        if raw_pub:
            public_key = _normalise_pem(raw_pub)

        if not private_key:
            logger.warning(
                "AUTH_JWT_PRIVATE_KEY is not set — token signing will fail for %s.",
                algorithm,
            )

    return JwtConfig(
        secret=secret,
        algorithm=algorithm,
        expires_seconds=expires_seconds,
        issuer=issuer,
        private_key=private_key,
        public_key=public_key,
    )


def _signing_key(config: JwtConfig) -> str:
    """Return the key used to *sign* tokens."""
    if config.algorithm in _RSA_ALGORITHMS:
        if not config.private_key:
            raise HTTPException(
                status_code=500,
                detail=f"{config.algorithm} requires AUTH_JWT_PRIVATE_KEY to be set",
            )
        return config.private_key
    return config.secret


def _verification_key(config: JwtConfig) -> str:
    """Return the key used to *verify* tokens."""
    if config.algorithm in _RSA_ALGORITHMS:
        # Prefer explicit public key; fall back to deriving from private key.
        if config.public_key:
            return config.public_key
        if config.private_key:
            return config.private_key  # PyJWT can extract the public key
        raise HTTPException(
            status_code=500,
            detail=f"{config.algorithm} requires AUTH_JWT_PUBLIC_KEY or AUTH_JWT_PRIVATE_KEY",
        )
    return config.secret


def build_access_token(*, subject: str, roles: list[str], config: JwtConfig) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=config.expires_seconds)

    payload: dict[str, Any] = {
        "sub": subject,
        "roles": roles,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": config.issuer,
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(payload, _signing_key(config), algorithm=config.algorithm)
    return token, config.expires_seconds


def decode_access_token(token: str, config: JwtConfig) -> dict[str, Any]:
    return jwt.decode(
        token,
        _verification_key(config),
        algorithms=[config.algorithm],
        options={"require": ["sub", "exp", "iat", "iss"]},
    )
