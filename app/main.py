import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import jwt
import httpx
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from app.cms_oauth import (
    get_cms_github_oauth_config,
    get_cms_frontend_base_url,
    get_oauth_state_secret,
    render_popup_error,
    render_popup_success,
    sign_oauth_state,
    verify_oauth_state,
)
from app.jwt_utils import APP_TITLE, _DEFAULT_SECRET, build_access_token, decode_access_token, get_jwt_config
from app.models import (
    HealthResponse,
    RevokeRequest,
    TokenRequest,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.rate_limit import limiter
from app.revocation import blocklist
from app.settings import get_allowed_origins
from app.roles import sanitize_roles

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Refuse to start in production if no real JWT secret is configured."""
    secret = os.getenv("AUTH_JWT_SECRET", _DEFAULT_SECRET)
    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    if secret == _DEFAULT_SECRET and environment == "production":
        raise RuntimeError(
            "AUTH_JWT_SECRET must be set to a strong secret in production. "
            "The default insecure value is not allowed."
        )
    yield


app = FastAPI(title=APP_TITLE, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def resolve_cms_callback_url(request: Request) -> str:
    oauth_config = get_cms_github_oauth_config()
    if oauth_config.redirect_uri:
        return oauth_config.redirect_uri
    return str(request.url_for("cms_oauth_callback"))


def _client_ip(request: Request) -> str:
    """Best-effort client IP: X-Forwarded-For (first hop) → direct peer."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _rate_limit_or_none(request: Request) -> JSONResponse | None:
    """Return a 429 JSONResponse if the caller is over their limit, else None."""
    ip = _client_ip(request)
    if limiter.is_allowed(ip):
        return None
    remaining = limiter.remaining(ip)
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Too many requests. Please try again later.",
            "retry_after_seconds": limiter.window_seconds,
        },
        headers={
            "Retry-After": str(limiter.window_seconds),
            "X-RateLimit-Remaining": str(remaining),
        },
    )


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/info")
async def info() -> dict:
    return {
        "service": APP_TITLE,
        "version": "0.1.0",
        "features": [
            "jwt-issue-verify",
            "role-based-access",
            "admin-subject-gating",
            "cms-github-oauth",
        ],
    }


@app.post("/auth/token", response_model=None)
async def issue_token(request: TokenRequest, raw_request: Request) -> TokenResponse | JSONResponse:
    blocked = _rate_limit_or_none(raw_request)
    if blocked:
        return blocked
    config = get_jwt_config()
    subject = request.subject.strip()
    roles = sanitize_roles(subject=subject, requested_roles=request.roles)
    token, expires_in = build_access_token(
        subject=subject,
        roles=roles,
        config=config,
    )
    return TokenResponse(access_token=token, token_type="bearer", expires_in=expires_in)


@app.post("/auth/verify", response_model=None)
async def verify_token(request: VerifyRequest, raw_request: Request) -> VerifyResponse | JSONResponse:
    blocked = _rate_limit_or_none(raw_request)
    if blocked:
        return blocked
    config = get_jwt_config()

    try:
        payload = decode_access_token(request.token, config)
    except jwt.PyJWTError:
        return VerifyResponse(active=False)

    jti = payload.get("jti")
    if jti and blocklist.is_revoked(jti):
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


@app.post("/auth/revoke", response_model=None)
async def revoke_token(request: RevokeRequest, raw_request: Request) -> JSONResponse:
    blocked = _rate_limit_or_none(raw_request)
    if blocked:
        return blocked
    config = get_jwt_config()

    try:
        payload = decode_access_token(request.token, config)
    except jwt.PyJWTError:
        return JSONResponse(
            status_code=400,
            content={"detail": "invalid or expired token"},
        )

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return JSONResponse(
            status_code=400,
            content={"detail": "token has no jti or exp claim"},
        )

    blocklist.revoke(jti, exp)
    return JSONResponse(status_code=200, content={"revoked": True})


@app.get("/cms/auth", response_model=None)
async def cms_oauth_authorize(
    request: Request,
    provider: str = Query(...),
    site_id: str = Query(...),
    scope: str = Query(""),
) -> RedirectResponse | JSONResponse:
    blocked = _rate_limit_or_none(request)
    if blocked:
        return blocked

    if provider != "github":
        callback_url = resolve_cms_callback_url(request)
        return RedirectResponse(url=f"{callback_url}?error=unsupported_provider")

    oauth_config = get_cms_github_oauth_config()
    if not oauth_config.client_id or not oauth_config.client_secret:
        callback_url = resolve_cms_callback_url(request)
        return RedirectResponse(
            url=f"{callback_url}?error=oauth_not_configured",
        )

    requested_scope = scope.strip() or oauth_config.default_scope
    signed_state = sign_oauth_state(
        site_id=site_id.strip(),
        scope=requested_scope,
        secret=get_oauth_state_secret(),
    )

    callback_url = resolve_cms_callback_url(request)
    auth_request = httpx.URL(oauth_config.authorize_url).copy_add_param("client_id", oauth_config.client_id)
    auth_request = auth_request.copy_add_param("redirect_uri", callback_url)
    auth_request = auth_request.copy_add_param("scope", requested_scope)
    auth_request = auth_request.copy_add_param("state", signed_state)

    return RedirectResponse(url=str(auth_request))


@app.get("/cms/callback", response_class=HTMLResponse)
async def cms_oauth_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
) -> HTMLResponse:
    provider = "github"
    app_base_url = get_cms_frontend_base_url()

    if error:
        details = error_description.strip() if error_description else error
        return HTMLResponse(render_popup_error(provider, details, app_base_url), status_code=400)

    if not code or not state:
        return HTMLResponse(
            render_popup_error(provider, "Missing OAuth callback parameters", app_base_url),
            status_code=400,
        )

    oauth_config = get_cms_github_oauth_config()
    if not oauth_config.client_id or not oauth_config.client_secret:
        return HTMLResponse(
            render_popup_error(provider, "OAuth provider is not configured", app_base_url),
            status_code=500,
        )

    verified_state = verify_oauth_state(
        state=state,
        secret=get_oauth_state_secret(),
        ttl_seconds=oauth_config.state_ttl_seconds,
    )
    if not verified_state:
        return HTMLResponse(
            render_popup_error(provider, "Invalid or expired OAuth state", app_base_url),
            status_code=400,
        )

    callback_url = resolve_cms_callback_url(request)

    token_payload = {
        "client_id": oauth_config.client_id,
        "client_secret": oauth_config.client_secret,
        "code": code,
        "redirect_uri": callback_url,
        "state": state,
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            token_response = await client.post(
                oauth_config.token_url,
                headers={"Accept": "application/json"},
                data=token_payload,
            )
            provider_data = token_response.json()
    except (httpx.HTTPError, ValueError, TypeError):
        return HTMLResponse(
            render_popup_error(provider, "OAuth token exchange failed", app_base_url),
            status_code=502,
        )

    access_token = provider_data.get("access_token")
    if not token_response.is_success or not isinstance(access_token, str) or not access_token:
        provider_error = provider_data.get("error_description") or provider_data.get("error")
        error_message = str(provider_error) if provider_error else "OAuth token exchange rejected"
        return HTMLResponse(render_popup_error(provider, error_message, app_base_url), status_code=400)

    payload = {
        "token": access_token,
        "provider": provider,
        "site_id": verified_state["site_id"],
        "scope": provider_data.get("scope", verified_state["scope"]),
        "token_type": provider_data.get("token_type", "bearer"),
    }

    return HTMLResponse(render_popup_success(provider, payload, app_base_url))
