import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

APP_TITLE = "auth-service"


class HealthResponse(BaseModel):
    status: str


class TokenRequest(BaseModel):
    subject: str = Field(min_length=3, max_length=120)
    roles: list[str] = Field(default_factory=list)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class VerifyRequest(BaseModel):
    token: str


class VerifyResponse(BaseModel):
    active: bool
    subject: str | None = None
    roles: list[str] | None = None
    exp: int | None = None
    issuer: str | None = None


class JwtConfig(BaseModel):
    secret: str
    algorithm: str
    expires_seconds: int
    issuer: str


def get_jwt_config() -> JwtConfig:
    secret = os.getenv("AUTH_JWT_SECRET", "dev-insecure-secret-change-me")
    algorithm = os.getenv("AUTH_JWT_ALGORITHM", "HS256")
    expires_seconds_raw = os.getenv("AUTH_TOKEN_EXPIRES_SECONDS", "3600")
    issuer = os.getenv("AUTH_ISSUER", APP_TITLE)

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


app = FastAPI(title=APP_TITLE)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/auth/token", response_model=TokenResponse)
async def issue_token(request: TokenRequest) -> TokenResponse:
    config = get_jwt_config()
    token, expires_in = build_access_token(
        subject=request.subject.strip(),
        roles=request.roles,
        config=config,
    )
    return TokenResponse(access_token=token, token_type="bearer", expires_in=expires_in)


@app.post("/auth/verify", response_model=VerifyResponse)
async def verify_token(request: VerifyRequest) -> VerifyResponse:
    config = get_jwt_config()

    try:
        payload = decode_access_token(request.token, config)
    except jwt.PyJWTError:
        return VerifyResponse(active=False)

    roles = payload.get("roles")
    if not isinstance(roles, list):
        roles = []

    return VerifyResponse(
        active=True,
        subject=str(payload.get("sub", "")) or None,
        roles=[str(role) for role in roles],
        exp=payload.get("exp"),
        issuer=payload.get("iss"),
    )
