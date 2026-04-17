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
    create_invite,
    create_or_get_oauth_user,
    create_password_reset_token,
    create_refresh_token,
    create_user_with_password,
    get_db_path,
    get_invite_by_token,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username,
    hash_password,
    init_db,
    mark_invite_used,
    mark_password_reset_used,
    revoke_refresh_token,
    update_user_password,
    update_user_roles,
    validate_and_get_refresh_token_user,
    validate_and_get_reset_token_user,
    verify_password,
)
from app.jwt_utils import APP_TITLE, _DEFAULT_SECRET, build_access_token, decode_access_token, get_jwt_config
from app.models import (
    AuthUserResponse,
    HealthResponse,
    InviteRequest,
    InviteResponse,
    LoginRequest,
    PasswordResetConfirmModel,
    PasswordResetRequestModel,
    RegisterRequest,
    RevokeRequest,
    TokenRequest,
    TokenResponse,
    UpdateRolesRequest,
    UpdateRolesResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.rate_limit import limiter
from app.revocation import blocklist
from app.roles import sanitize_roles
from app.settings import get_allowed_origins
from app.email_sender import send_invite_email, send_password_reset_email
from app.user_oauth import (
    fetch_github_user,
    fetch_github_user_email,
    fetch_google_user,
    get_user_github_oauth_config,
    get_user_google_oauth_config,
    get_user_oauth_state_secret,
    render_user_popup_error,
    render_user_popup_success,
    sign_client_portal_oauth_state,
    sign_dashboard_oauth_state,
    sign_user_oauth_state,
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


def _roles_for_user(user) -> list[str]:
    """Return roles from DB if set, otherwise fall back to env-based logic."""
    if user.roles:
        import json
        try:
            return json.loads(user.roles)
        except (json.JSONDecodeError, TypeError):
            pass
    roles = ["user", "planner"]
    if user.username in _admin_subjects():
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


_REFRESH_COOKIE_NAME = "refresh_token"
_REFRESH_COOKIE_MAX_AGE = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", str(7 * 24 * 3600)))


async def _build_auth_response(user, roles: list[str]) -> tuple[AuthUserResponse, str]:
    """Build an AuthUserResponse and a fresh raw refresh token for cookie setting."""
    access_token, expires_in = _build_user_token(user.id, roles)
    raw_refresh = await create_refresh_token(get_db_path(), user.id)
    response_body = AuthUserResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        user_id=user.id,
        username=user.username,
        roles=roles,
    )
    return response_body, raw_refresh


def _set_refresh_cookie(response, raw_refresh: str) -> None:
    """Attach a secure httpOnly refresh token cookie to the given Response object."""
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=raw_refresh,
        max_age=_REFRESH_COOKIE_MAX_AGE,
        httponly=True,
        secure=os.getenv("ENVIRONMENT", "development").strip().lower() == "production",
        samesite="lax",
        path="/auth",
    )


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
    request: RegisterRequest,
    raw_request: Request,
    invite_token: str | None = Query(default=None, alias="token"),
) -> AuthUserResponse | JSONResponse:
    blocked = _rate_limit_or_none(raw_request)
    if blocked:
        return blocked

    # Validate invite token if provided
    invite = None
    if invite_token:
        from app.database import _is_expired
        invite = await get_invite_by_token(get_db_path(), invite_token)
        if invite is None or invite.used_at is not None or _is_expired(invite.expires_at):
            return JSONResponse(status_code=400, content={"detail": "Invalid or expired invite link."})
        # Ensure the email matches the invite
        if invite.email != request.username.lower().strip():
            return JSONResponse(status_code=400, content={"detail": "Email does not match the invite."})

    pw_hash = hash_password(request.password)
    try:
        user = await create_user_with_password(get_db_path(), request.username, pw_hash)
    except ValueError:
        return JSONResponse(
            status_code=409,
            content={"detail": "Email address already registered. Please use a different email address."},
        )

    # Assign client role for invite-based registrations, otherwise default roles
    if invite:
        roles = ["user", "client"]
        await update_user_roles(get_db_path(), user.id, roles)
        await mark_invite_used(get_db_path(), invite_token)
    else:
        roles = _roles_for_user(user)

    response_body, raw_refresh = await _build_auth_response(user, roles)
    json_response = JSONResponse(status_code=201, content=response_body.model_dump())
    _set_refresh_cookie(json_response, raw_refresh)
    return json_response


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

    roles = _roles_for_user(user)
    response_body, raw_refresh = await _build_auth_response(user, roles)
    json_response = JSONResponse(content=response_body.model_dump())
    _set_refresh_cookie(json_response, raw_refresh)
    return json_response


# ---------------------------------------------------------------------------
# Admin: manage user roles
# ---------------------------------------------------------------------------

@app.patch("/admin/users/{user_id}/roles", response_model=None)
async def admin_update_user_roles(
    user_id: str,
    request: UpdateRolesRequest,
    raw_request: Request,
) -> UpdateRolesResponse | JSONResponse:
    # Verify caller is admin via JWT
    auth_header = raw_request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Authorization header required"},
        )
    token = auth_header[len("Bearer "):]
    try:
        claims = decode_access_token(token)
    except Exception:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or expired token"},
        )
    caller_roles = claims.get("roles", [])
    if "admin" not in caller_roles:
        return JSONResponse(
            status_code=403,
            content={"detail": "Admin role required"},
        )

    # Validate requested roles
    from app.roles import DEFAULT_ALLOWED_ROLES
    for role in request.roles:
        if role.lower() not in DEFAULT_ALLOWED_ROLES:
            return JSONResponse(
                status_code=422,
                content={"detail": f"Invalid role: {role}"},
            )

    # Verify target user exists
    user = await get_user_by_id(get_db_path(), user_id)
    if user is None:
        return JSONResponse(
            status_code=404,
            content={"detail": "User not found"},
        )

    normalized = [r.lower() for r in request.roles]
    await update_user_roles(get_db_path(), user_id, normalized)
    return UpdateRolesResponse(user_id=user_id, roles=normalized)


# ---------------------------------------------------------------------------
# Invite flow (admin-only)
# ---------------------------------------------------------------------------

_INVITE_BASE_URL = os.getenv("INVITE_BASE_URL", "").strip()
_INVITE_EXPIRES_HOURS = int(os.getenv("INVITE_EXPIRES_HOURS", "72"))


def _require_admin(raw_request: Request) -> dict | JSONResponse:
    """Decode the bearer token and return claims if admin, else a 401/403 JSONResponse."""
    auth_header = raw_request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Authorization header required"})
    token = auth_header[len("Bearer "):]
    try:
        config = get_jwt_config()
        claims = decode_access_token(token, config)
    except Exception:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})
    if "admin" not in claims.get("roles", []):
        return JSONResponse(status_code=403, content={"detail": "Admin access required"})
    return claims


@app.post("/auth/invite", response_model=InviteResponse, status_code=201)
async def create_invite_link(
    body: InviteRequest, raw_request: Request
) -> InviteResponse | JSONResponse:
    claims = _require_admin(raw_request)
    if isinstance(claims, JSONResponse):
        return claims

    invite_record = await create_invite(get_db_path(), body.email)
    base = _INVITE_BASE_URL.rstrip("/")
    invite_url = f"{base}/register?token={invite_record.token}" if base else f"/register?token={invite_record.token}"

    await send_invite_email(body.email, invite_url)
    return InviteResponse(
        invite_url=invite_url,
        email=body.email,
        expires_in_hours=_INVITE_EXPIRES_HOURS,
    )


# ---------------------------------------------------------------------------
# Refresh, logout, password reset
# ---------------------------------------------------------------------------

@app.post("/auth/refresh", response_model=None)
async def refresh_access_token(raw_request: Request) -> JSONResponse:
    raw_refresh = raw_request.cookies.get(_REFRESH_COOKIE_NAME)
    if not raw_refresh:
        return JSONResponse(status_code=401, content={"detail": "No refresh token"})

    user = await validate_and_get_refresh_token_user(get_db_path(), raw_refresh)
    if user is None:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired refresh token"})

    roles = _roles_for_user(user)
    token, expires_in = _build_user_token(user.id, roles)
    return JSONResponse(content={"access_token": token, "token_type": "bearer", "expires_in": expires_in})


@app.post("/auth/logout", status_code=204)
async def logout_user(raw_request: Request) -> JSONResponse:
    raw_refresh = raw_request.cookies.get(_REFRESH_COOKIE_NAME)
    if raw_refresh:
        await revoke_refresh_token(get_db_path(), raw_refresh)
    response = JSONResponse(status_code=204, content=None)
    response.delete_cookie(key=_REFRESH_COOKIE_NAME, path="/auth")
    return response


@app.post("/auth/password/reset-request", status_code=202)
async def password_reset_request(body: PasswordResetRequestModel) -> JSONResponse:
    user = await get_user_by_email(get_db_path(), body.email)
    if user is not None and user.password_hash is not None:
        raw_token = await create_password_reset_token(get_db_path(), user.id)
        base = _INVITE_BASE_URL.rstrip("/")
        reset_url = f"{base}/reset-password?token={raw_token}" if base else f"/reset-password?token={raw_token}"
        await send_password_reset_email(user.email or user.username, reset_url)
    # Always return 202 to avoid revealing whether the email is registered
    return JSONResponse(status_code=202, content={"detail": "If that email is registered, a reset link has been sent."})


@app.post("/auth/password/reset", status_code=200)
async def password_reset_confirm(body: PasswordResetConfirmModel) -> JSONResponse:
    user = await validate_and_get_reset_token_user(get_db_path(), body.token)
    if user is None:
        return JSONResponse(status_code=400, content={"detail": "Invalid or expired reset token"})

    new_hash = hash_password(body.password)
    await update_user_password(get_db_path(), user.id, new_hash)
    await mark_password_reset_used(get_db_path(), body.token)
    return JSONResponse(content={"detail": "Password updated successfully"})

def _resolve_user_oauth_callback_url(request: Request) -> str:
    configured = os.getenv("USER_OAUTH_CALLBACK_URL", "").strip()
    if configured:
        return configured
    return str(request.url_for("user_oauth_callback"))


@app.get("/user/oauth/github", response_model=None)
async def user_oauth_github_authorize(
    request: Request,
    scope: str | None = Query(default=None),
    redirect_uri: str | None = Query(default=None),
) -> RedirectResponse | HTMLResponse:
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

    if scope == "client_portal" and redirect_uri:
        signed_state = sign_client_portal_oauth_state(
            provider="github",
            redirect_uri=redirect_uri,
            secret=get_user_oauth_state_secret(),
        )
    else:
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
async def user_oauth_google_authorize(
    request: Request,
    scope: str | None = Query(default=None),
    redirect_uri: str | None = Query(default=None),
) -> RedirectResponse | HTMLResponse:
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

    if scope == "client_portal" and redirect_uri:
        signed_state = sign_client_portal_oauth_state(
            provider="google",
            redirect_uri=redirect_uri,
            secret=get_user_oauth_state_secret(),
        )
    else:
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
    state_data = verify_oauth_state(
        state=state,
        secret=get_user_oauth_state_secret(),
        ttl_seconds=ttl,
    )
    if not state_data:
        return HTMLResponse(
            render_user_popup_error("Invalid or expired OAuth state", app_base_url),
            status_code=400,
        )

    scope = state_data.get("scope", "user_login")
    provider = state_data.get("site_id", "")
    if not provider:
        return HTMLResponse(
            render_user_popup_error("Invalid OAuth state: missing provider", app_base_url),
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
            provider_email: str | None = user_info.get("email") or await fetch_github_user_email(provider_access_token)
        else:
            user_info = await fetch_google_user(provider_access_token)
            provider_user_id = str(user_info.get("id", ""))
            provider_username = (
                user_info.get("name")
                or user_info.get("email", "").split("@")[0]
                or "google_user"
            )
            provider_email = user_info.get("email") or None
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
            get_db_path(), provider, provider_user_id, provider_username, provider_email=provider_email
        )
    except Exception as exc:
        logger.exception("Database error during OAuth user lookup: %s", exc)
        return HTMLResponse(
            render_user_popup_error("Internal server error", app_base_url),
            status_code=500,
        )

    roles = _roles_for_user(user)
    token, expires_in = _build_user_token(user.id, roles)

    if scope == "client_portal":
        portal_redirect_uri = state_data.get("redirect_uri", "")
        if not portal_redirect_uri:
            return HTMLResponse(
                render_user_popup_error("Missing redirect_uri in portal OAuth state", app_base_url),
                status_code=400,
            )
        # Basic open-redirect guard: only allow http(s) URIs
        if not portal_redirect_uri.startswith(("http://", "https://")):
            return HTMLResponse(
                render_user_popup_error("Invalid redirect_uri", app_base_url),
                status_code=400,
            )
        # Ensure the client role is present in the JWT for portal access
        if "client" not in roles:
            roles = list(roles) + ["client"]
            token, expires_in = _build_user_token(user.id, roles)
        raw_refresh = await create_refresh_token(get_db_path(), user.id)
        redirect = RedirectResponse(
            f"{portal_redirect_uri}#token={token}",
            status_code=303,
        )
        _set_refresh_cookie(redirect, raw_refresh)
        return redirect

    if scope == "dashboard_login":
        # Admin redirect flow — check admin membership
        admin_subjects = _admin_subjects()
        if admin_subjects and user.id not in admin_subjects and user.username not in admin_subjects:
            return HTMLResponse(
                "<html><body style='font-family:monospace;background:#09090b;color:#fca5a5;"
                "display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0'>"
                "<p>Access denied: admin account required.</p></body></html>",
                status_code=403,
            )
        spend_url = os.getenv(
            "SPEND_DASHBOARD_URL",
            "https://dynamodb-dashboard-rodmen07.fly.dev/spend",
        )
        return RedirectResponse(f"{spend_url}#token={token}", status_code=303)

    # Default: user_login popup flow
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


# ---------------------------------------------------------------------------
# Dashboard admin login portal
# ---------------------------------------------------------------------------

_DASHBOARD_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Dashboard Login</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #09090b;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    color: #f4f4f5;
  }
  .card {
    width: 100%;
    max-width: 380px;
    background: #18181b;
    border: 1px solid rgba(113,113,122,.3);
    border-radius: 1.5rem;
    padding: 2rem;
    box-shadow: 0 25px 50px rgba(0,0,0,.6);
  }
  h1 { font-size: 1.125rem; font-weight: 700; color: #fbbf24; margin-bottom: .25rem; }
  p.sub { font-size: .75rem; color: #71717a; margin-bottom: 1.5rem; }
  .github-btn {
    display: block; text-align: center; padding: .625rem;
    border: 1px solid rgba(113,113,122,.4); border-radius: .75rem;
    color: #a1a1aa; font-size: .875rem; text-decoration: none;
    transition: border-color .15s, color .15s;
  }
  .github-btn:hover { border-color: rgba(161,161,170,.6); color: #d4d4d8; }
  .footer { margin-top: 1.25rem; font-size: .65rem; color: #52525b; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <h1>Dashboard Admin</h1>
  <p class="sub">Sign in to access the spend dashboard</p>
  <a href="/dashboard/oauth/github" class="github-btn">Sign in with GitHub &rarr;</a>
  <p class="footer">Admin access only</p>
</div>
</body>
</html>"""


@app.get("/dashboard/oauth/github", response_model=None)
async def dashboard_oauth_github(request: Request) -> RedirectResponse | HTMLResponse:
    blocked = _rate_limit_or_none(request)
    if blocked:
        return blocked

    oauth_config = get_user_github_oauth_config()
    if not oauth_config.client_id or not oauth_config.client_secret:
        return HTMLResponse(
            "<p>GitHub OAuth is not configured</p>",
            status_code=500,
        )

    signed_state = sign_dashboard_oauth_state(secret=get_user_oauth_state_secret())

    callback_url = _resolve_user_oauth_callback_url(request)
    auth_url = httpx.URL(oauth_config.authorize_url)
    auth_url = auth_url.copy_add_param("client_id", oauth_config.client_id)
    auth_url = auth_url.copy_add_param("redirect_uri", callback_url)
    auth_url = auth_url.copy_add_param("scope", oauth_config.default_scope)
    auth_url = auth_url.copy_add_param("state", signed_state)

    return RedirectResponse(url=str(auth_url))


@app.get("/dashboard/login", response_class=HTMLResponse)
async def dashboard_login_page() -> HTMLResponse:
    return HTMLResponse(_DASHBOARD_LOGIN_HTML)
