import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

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
from app.database import (
    create_or_get_oauth_user,
    create_user_with_password,
    get_db_path,
    get_user_by_username,
    hash_password,
    init_db,
    verify_password,
)
from app.jwt_utils import APP_TITLE, _DEFAULT_SECRET, build_access_token, decode_access_token, get_jwt_config
from app.models import (
    AuthUserResponse,
    HealthResponse,
    LoginRequest,
    RegisterRequest,
    RevokeRequest,
    TokenRequest,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.rate_limit import limiter
from app.revocation import blocklist
from app.roles import sanitize_roles
from app.settings import get_allowed_origins
from app.user_oauth import (
    fetch_github_user,
    fetch_google_user,
    get_user_github_oauth_config,
    get_user_google_oauth_config,
    get_user_oauth_state_secret,
    render_user_popup_error,
    render_user_popup_success,
    sign_user_oauth_state,
    verify_user_oauth_state,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Startup validation, DB init, and graceful shutdown hooks."""
    secret = os.getenv("AUTH_JWT_SECRET", _DEFAULT_SECRET)
    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    if secret == _DEFAULT_SECRET and environment == "production":
        raise RuntimeError(
            "AUTH_JWT_SECRET must be set to a strong secret in production. "
            "The default insecure value is not allowed."
        )

    await init_db(get_db_path())

    yield

    limiter.flush()


app = FastAPI(title=APP_TITLE, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_cms_callback_url(request: Request) -> str:
    oauth_config = get_cms_github_oauth_config()
    if oauth_config.redirect_uri:
        return oauth_config.redirect_uri
    return str(request.url_for("cms_oauth_callback"))


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _rate_limit_or_none(request: Request) -> JSONResponse | None:
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


def _admin_subjects() -> set[str]:
    raw = os.getenv("AUTH_ADMIN_SUBJECTS", "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def _roles_for_username(username: str) -> list[str]:
    """Return ['user', 'planner'] or ['user', 'planner', 'admin'] based on AUTH_ADMIN_SUBJECTS."""
    roles = ["user", "planner"]
    if username in _admin_subjects():
        roles.append("admin")
    return roles


def _build_user_token(user_id: str, roles: list[str]) -> tuple[str, int]:
    """Issue a JWT with the user UUID as subject. Email is not embedded in the token."""
    import uuid as _uuid
    from datetime import datetime, timedelta, timezone
    from app.jwt_utils import _signing_key

    config = get_jwt_config()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=config.expires_seconds)

    payload: dict[str, Any] = {
        "sub": user_id,
        "roles": roles,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": config.issuer,
        "jti": str(_uuid.uuid4()),
    }

    token = jwt.encode(payload, _signing_key(config), algorithm=config.algorithm)
    return token, config.expires_seconds


# ---------------------------------------------------------------------------
# Existing endpoints (unchanged)
# ---------------------------------------------------------------------------

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
            "user-password-auth",
            "user-github-oauth",
            "user-google-oauth",
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


# ---------------------------------------------------------------------------
# CMS OAuth (admin — unchanged)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# User password auth
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=None, status_code=201)
async def register_user(
    request: RegisterRequest, raw_request: Request
) -> AuthUserResponse | JSONResponse:
    blocked = _rate_limit_or_none(raw_request)
    if blocked:
        return blocked

    pw_hash = hash_password(request.password)
    try:
        user = await create_user_with_password(get_db_path(), request.username, pw_hash)
    except ValueError:
        return JSONResponse(
            status_code=409,
            content={"detail": "Email address already registered. Please use a different email address."},
        )

    roles = _roles_for_username(user.username)
    token, expires_in = _build_user_token(user.id, roles)

    return AuthUserResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user_id=user.id,
        username=user.username,
        roles=roles,
    )


@app.post("/auth/login", response_model=None)
async def login_user(
    request: LoginRequest, raw_request: Request
) -> AuthUserResponse | JSONResponse:
    blocked = _rate_limit_or_none(raw_request)
    if blocked:
        return blocked

    user = await get_user_by_username(get_db_path(), request.username)

    _invalid = JSONResponse(
        status_code=401,
        content={"detail": "Invalid username or password."},
    )

    if user is None:
        return _invalid

    if user.password_hash is None:
        return JSONResponse(
            status_code=400,
            content={"detail": "This account uses OAuth sign-in. Please use GitHub or Google to log in."},
        )

    if not verify_password(request.password, user.password_hash):
        return _invalid

    roles = _roles_for_username(user.username)
    token, expires_in = _build_user_token(user.id, roles)

    return AuthUserResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user_id=user.id,
        username=user.username,
        roles=roles,
    )


# ---------------------------------------------------------------------------
# User OAuth — GitHub
# ---------------------------------------------------------------------------

def _resolve_user_oauth_callback_url(request: Request) -> str:
    configured = os.getenv("USER_OAUTH_CALLBACK_URL", "").strip()
    if configured:
        return configured
    return str(request.url_for("user_oauth_callback"))


@app.get("/user/oauth/github", response_model=None)
async def user_oauth_github_authorize(request: Request) -> RedirectResponse | HTMLResponse:
    blocked = _rate_limit_or_none(request)
    if blocked:
        return blocked

    oauth_config = get_user_github_oauth_config()
    if not oauth_config.client_id or not oauth_config.client_secret:
        app_base_url = get_cms_frontend_base_url()
        return HTMLResponse(
            render_user_popup_error("GitHub OAuth is not configured", app_base_url),
            status_code=500,
        )

    signed_state = sign_user_oauth_state(
        provider="github",
        secret=get_user_oauth_state_secret(),
    )

    callback_url = _resolve_user_oauth_callback_url(request)
    auth_url = httpx.URL(oauth_config.authorize_url)
    auth_url = auth_url.copy_add_param("client_id", oauth_config.client_id)
    auth_url = auth_url.copy_add_param("redirect_uri", callback_url)
    auth_url = auth_url.copy_add_param("scope", oauth_config.default_scope)
    auth_url = auth_url.copy_add_param("state", signed_state)

    return RedirectResponse(url=str(auth_url))


@app.get("/user/oauth/google", response_model=None)
async def user_oauth_google_authorize(request: Request) -> RedirectResponse | HTMLResponse:
    blocked = _rate_limit_or_none(request)
    if blocked:
        return blocked

    oauth_config = get_user_google_oauth_config()
    if not oauth_config.client_id or not oauth_config.client_secret:
        app_base_url = get_cms_frontend_base_url()
        return HTMLResponse(
            render_user_popup_error("Google OAuth is not configured", app_base_url),
            status_code=500,
        )

    signed_state = sign_user_oauth_state(
        provider="google",
        secret=get_user_oauth_state_secret(),
    )

    callback_url = _resolve_user_oauth_callback_url(request)
    auth_url = httpx.URL(oauth_config.authorize_url)
    auth_url = auth_url.copy_add_param("client_id", oauth_config.client_id)
    auth_url = auth_url.copy_add_param("redirect_uri", callback_url)
    auth_url = auth_url.copy_add_param("scope", oauth_config.default_scope)
    auth_url = auth_url.copy_add_param("state", signed_state)
    auth_url = auth_url.copy_add_param("response_type", "code")
    auth_url = auth_url.copy_add_param("access_type", "online")

    return RedirectResponse(url=str(auth_url))


# ---------------------------------------------------------------------------
# User OAuth — shared callback
# ---------------------------------------------------------------------------

@app.get("/user/oauth/callback", response_class=HTMLResponse, name="user_oauth_callback")
async def user_oauth_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
) -> HTMLResponse:
    app_base_url = get_cms_frontend_base_url()

    if error:
        details = error_description.strip() if error_description else error
        return HTMLResponse(render_user_popup_error(details, app_base_url), status_code=400)

    if not code or not state:
        return HTMLResponse(
            render_user_popup_error("Missing OAuth callback parameters", app_base_url),
            status_code=400,
        )

    ttl = max(60, int(os.getenv("USER_OAUTH_STATE_TTL_SECONDS", "600")))
    provider = verify_user_oauth_state(
        state=state,
        secret=get_user_oauth_state_secret(),
        ttl_seconds=ttl,
    )
    if not provider:
        return HTMLResponse(
            render_user_popup_error("Invalid or expired OAuth state", app_base_url),
            status_code=400,
        )

    callback_url = _resolve_user_oauth_callback_url(request)

    # Exchange code for provider access token
    try:
        if provider == "github":
            oauth_config = get_user_github_oauth_config()
            token_payload = {
                "client_id": oauth_config.client_id,
                "client_secret": oauth_config.client_secret,
                "code": code,
                "redirect_uri": callback_url,
            }
            async with httpx.AsyncClient(timeout=20) as client:
                token_resp = await client.post(
                    oauth_config.token_url,
                    headers={"Accept": "application/json"},
                    data=token_payload,
                )
                token_data = token_resp.json()

        elif provider == "google":
            oauth_config = get_user_google_oauth_config()
            token_payload = {
                "client_id": oauth_config.client_id,
                "client_secret": oauth_config.client_secret,
                "code": code,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            }
            async with httpx.AsyncClient(timeout=20) as client:
                token_resp = await client.post(
                    oauth_config.token_url,
                    headers={"Accept": "application/json"},
                    data=token_payload,
                )
                token_data = token_resp.json()

        else:
            return HTMLResponse(
                render_user_popup_error(f"Unsupported provider: {provider}", app_base_url),
                status_code=400,
            )

    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.exception("OAuth token exchange failed for provider %s: %s", provider, exc)
        return HTMLResponse(
            render_user_popup_error("OAuth token exchange failed", app_base_url),
            status_code=502,
        )

    provider_access_token = token_data.get("access_token")
    if not isinstance(provider_access_token, str) or not provider_access_token:
        provider_error = token_data.get("error_description") or token_data.get("error")
        msg = str(provider_error) if provider_error else "OAuth token exchange rejected"
        return HTMLResponse(render_user_popup_error(msg, app_base_url), status_code=400)

    # Fetch user info from provider
    try:
        if provider == "github":
            user_info = await fetch_github_user(provider_access_token)
            provider_user_id = str(user_info.get("id", ""))
            provider_username = user_info.get("login") or user_info.get("name") or "github_user"
        else:
            user_info = await fetch_google_user(provider_access_token)
            provider_user_id = str(user_info.get("id", ""))
            provider_username = (
                user_info.get("name")
                or user_info.get("email", "").split("@")[0]
                or "google_user"
            )
    except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
        logger.exception("Failed to fetch user info from %s: %s", provider, exc)
        return HTMLResponse(
            render_user_popup_error("Failed to fetch user info from provider", app_base_url),
            status_code=502,
        )

    if not provider_user_id:
        return HTMLResponse(
            render_user_popup_error("Provider did not return a user ID", app_base_url),
            status_code=502,
        )

    try:
        user, _created = await create_or_get_oauth_user(
            get_db_path(), provider, provider_user_id, provider_username
        )
    except Exception as exc:
        logger.exception("Database error during OAuth user lookup: %s", exc)
        return HTMLResponse(
            render_user_popup_error("Internal server error", app_base_url),
            status_code=500,
        )

    roles = _roles_for_username(user.username)
    token, expires_in = _build_user_token(user.id, roles)

    return HTMLResponse(
        render_user_popup_success(
            {
                "access_token": token,
                "token_type": "bearer",
                "expires_in": expires_in,
                "user_id": user.id,
                "username": user.username,
                "roles": roles,
            },
            app_base_url,
        )
    )
