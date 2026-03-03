import jwt
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.jwt_utils import APP_TITLE, build_access_token, decode_access_token, get_jwt_config
from app.models import (
    HealthResponse,
    TokenRequest,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.settings import get_allowed_origins


app = FastAPI(title=APP_TITLE)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
