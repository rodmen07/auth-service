import json
import logging
import os
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from app.cms_oauth import (
    get_cms_frontend_base_url,
    sign_oauth_state,
    verify_oauth_state,
)

logger = logging.getLogger(__name__)

_DEFAULT_USER_OAUTH_STATE_SECRET = "user-oauth-state-insecure-default"

SUPPORTED_PROVIDERS = ("github", "google")


def get_user_oauth_state_secret() -> str:
    secret = os.getenv("USER_OAUTH_STATE_SECRET", "").strip()
    if not secret:
        logger.warning(
            "USER_OAUTH_STATE_SECRET is not set — using an insecure default. "
            "Set USER_OAUTH_STATE_SECRET to a strong random value in production."
        )
        return _DEFAULT_USER_OAUTH_STATE_SECRET
    return secret


# ---------------------------------------------------------------------------
# GitHub OAuth config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UserGithubOAuthConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    authorize_url: str
    token_url: str
    default_scope: str
    state_ttl_seconds: int


def get_user_github_oauth_config() -> UserGithubOAuthConfig:
    return UserGithubOAuthConfig(
        client_id=os.getenv("USER_GITHUB_CLIENT_ID", "").strip(),
        client_secret=os.getenv("USER_GITHUB_CLIENT_SECRET", "").strip(),
        redirect_uri=os.getenv("USER_GITHUB_REDIRECT_URI", "").strip(),
        authorize_url=os.getenv(
            "USER_GITHUB_AUTHORIZE_URL",
            "https://github.com/login/oauth/authorize",
        ).strip(),
        token_url=os.getenv(
            "USER_GITHUB_TOKEN_URL",
            "https://github.com/login/oauth/access_token",
        ).strip(),
        default_scope=os.getenv("USER_GITHUB_SCOPE", "read:user user:email").strip() or "read:user user:email",
        state_ttl_seconds=max(60, int(os.getenv("USER_OAUTH_STATE_TTL_SECONDS", "600"))),
    )


# ---------------------------------------------------------------------------
# Google OAuth config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UserGoogleOAuthConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    authorize_url: str
    token_url: str
    default_scope: str
    state_ttl_seconds: int


def get_user_google_oauth_config() -> UserGoogleOAuthConfig:
    return UserGoogleOAuthConfig(
        client_id=os.getenv("USER_GOOGLE_CLIENT_ID", "").strip(),
        client_secret=os.getenv("USER_GOOGLE_CLIENT_SECRET", "").strip(),
        redirect_uri=os.getenv("USER_GOOGLE_REDIRECT_URI", "").strip(),
        authorize_url=os.getenv(
            "USER_GOOGLE_AUTHORIZE_URL",
            "https://accounts.google.com/o/oauth2/v2/auth",
        ).strip(),
        token_url=os.getenv(
            "USER_GOOGLE_TOKEN_URL",
            "https://oauth2.googleapis.com/token",
        ).strip(),
        default_scope=os.getenv("USER_GOOGLE_SCOPE", "openid email profile").strip() or "openid email profile",
        state_ttl_seconds=max(60, int(os.getenv("USER_OAUTH_STATE_TTL_SECONDS", "600"))),
    )


# ---------------------------------------------------------------------------
# Provider user-info fetching
# ---------------------------------------------------------------------------

async def fetch_github_user(access_token: str) -> dict:
    """Return the GitHub user object for the given access token."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        resp.raise_for_status()
        return resp.json()


async def fetch_github_user_email(access_token: str) -> str | None:
    """Return the primary verified email for the GitHub user, or None if unavailable."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://api.github.com/user/emails",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        if not resp.is_success:
            return None
        emails = resp.json()
    if not isinstance(emails, list):
        return None
    # Prefer primary + verified email
    for entry in emails:
        if entry.get("primary") and entry.get("verified"):
            return entry.get("email")
    # Fall back to any verified email
    for entry in emails:
        if entry.get("verified"):
            return entry.get("email")
    return None


async def fetch_google_user(access_token: str) -> dict:
    """Return the Google userinfo object for the given access token."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Popup HTML rendering
# ---------------------------------------------------------------------------

def _extract_origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return "*"


def render_user_popup_success(payload: dict, app_base_url: str) -> str:
    """
    Render the popup HTML that posts 'authorization:user:success:<json>' back to the
    opener window, then closes itself. *payload* contains the issued JWT and user info.
    """
    payload_json = json.dumps(payload)
    target_origin = _extract_origin(app_base_url)
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Sign In Complete</title>
  </head>
  <body>
    <script>
      (function() {{
        var targetOrigin = {json.dumps(target_origin)};
        var success = 'authorization:user:success:' + {json.dumps(payload_json)};

        function post(message) {{
          if (window.opener) {{
            window.opener.postMessage(message, targetOrigin);
          }}
        }}

        window.addEventListener('message', function(event) {{
          if (event.origin !== targetOrigin) {{ return; }}
          if (event.data === 'authorizing:user') {{
            post(event.data);
            post(success);
            window.close();
          }}
        }});

        post('authorizing:user');
      }})();
    </script>
    <main style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:1.25rem;">
      <p style="margin:0;">Sign in complete. You can close this window.</p>
    </main>
  </body>
</html>
"""


def render_user_popup_error(message: str, app_base_url: str) -> str:
    payload_json = json.dumps({"message": message})
    target_origin = _extract_origin(app_base_url)
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Sign In Failed</title>
  </head>
  <body>
    <script>
      (function() {{
        var targetOrigin = {json.dumps(target_origin)};
        var failure = 'authorization:user:error:' + {json.dumps(payload_json)};

        function post(message) {{
          if (window.opener) {{
            window.opener.postMessage(message, targetOrigin);
          }}
        }}

        window.addEventListener('message', function(event) {{
          if (event.origin !== targetOrigin) {{ return; }}
          if (event.data === 'authorizing:user') {{
            post(event.data);
            post(failure);
            window.close();
          }}
        }});

        post('authorizing:user');
      }})();
    </script>
    <main style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:1.25rem;">
      <p style="margin:0;">Sign in failed: {message}</p>
    </main>
  </body>
</html>
"""


# ---------------------------------------------------------------------------
# Shared state helpers — thin wrappers re-using cms_oauth primitives
# ---------------------------------------------------------------------------

def sign_user_oauth_state(*, provider: str, secret: str) -> str:
    """Sign an OAuth state token that also embeds the provider name."""
    return sign_oauth_state(site_id=provider, scope="user_login", secret=secret)


def verify_user_oauth_state(*, state: str, secret: str, ttl_seconds: int) -> str | None:
    """
    Verify the state token. Returns the provider string on success, None on failure.
    """
    result = verify_oauth_state(state=state, secret=secret, ttl_seconds=ttl_seconds)
    if result is None:
        return None
    return result.get("site_id")  # we stored provider in the site_id field


def sign_dashboard_oauth_state(*, secret: str) -> str:
    """Sign an OAuth state token for the dashboard admin login flow."""
    return sign_oauth_state(site_id="github", scope="dashboard_login", secret=secret)


def sign_client_portal_oauth_state(*, provider: str, redirect_uri: str, secret: str) -> str:
    """Sign an OAuth state token for the client portal login flow.

    The redirect_uri is embedded in the signed state so the callback can
    redirect back to the frontend with the JWT.
    """
    return sign_oauth_state(
        site_id=provider,
        scope="client_portal",
        secret=secret,
        redirect_uri=redirect_uri,
    )
