import jwt
import httpx
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from app.cms_oauth import (
    get_cms_github_oauth_config,
    get_cms_frontend_base_url,
    render_popup_error,
    render_popup_success,
    sign_oauth_state,
    verify_oauth_state,
)
from app.jwt_utils import APP_TITLE, build_access_token, decode_access_token, get_jwt_config
from app.models import (
    HealthResponse,
    TokenRequest,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.settings import get_allowed_origins
from app.roles import sanitize_roles


app = FastAPI(title=APP_TITLE)

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


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/auth/token", response_model=TokenResponse)
async def issue_token(request: TokenRequest) -> TokenResponse:
    config = get_jwt_config()
    subject = request.subject.strip()
    roles = sanitize_roles(subject=subject, requested_roles=request.roles)
    token, expires_in = build_access_token(
        subject=subject,
        roles=roles,
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


@app.get("/cms/auth")
async def cms_oauth_authorize(
    request: Request,
    provider: str = Query(...),
    site_id: str = Query(...),
    scope: str = Query(""),
) -> RedirectResponse:
    if provider != "github":
        callback_url = resolve_cms_callback_url(request)
        return RedirectResponse(url=f"{callback_url}?error=unsupported_provider")

    oauth_config = get_cms_github_oauth_config()
    if not oauth_config.client_id or not oauth_config.client_secret:
        callback_url = resolve_cms_callback_url(request)
        return RedirectResponse(
            url=f"{callback_url}?error=oauth_not_configured",
        )

    jwt_config = get_jwt_config()
    requested_scope = scope.strip() or oauth_config.default_scope
    signed_state = sign_oauth_state(
        site_id=site_id.strip(),
        scope=requested_scope,
        secret=jwt_config.secret,
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

    jwt_config = get_jwt_config()
    verified_state = verify_oauth_state(
        state=state,
        secret=jwt_config.secret,
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
