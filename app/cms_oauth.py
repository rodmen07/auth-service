import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class CmsGithubOAuthConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    authorize_url: str
    token_url: str
    default_scope: str
    state_ttl_seconds: int

def get_cms_frontend_base_url() -> str:
    configured = os.getenv("CMS_FRONTEND_BASE_URL", "").strip()
    base_url = configured or "https://rodmen07.github.io/frontend-service/"
    return base_url if base_url.endswith("/") else f"{base_url}/"


def get_cms_github_oauth_config() -> CmsGithubOAuthConfig:
    return CmsGithubOAuthConfig(
        client_id=os.getenv("CMS_GITHUB_CLIENT_ID", "").strip(),
        client_secret=os.getenv("CMS_GITHUB_CLIENT_SECRET", "").strip(),
        redirect_uri=os.getenv("CMS_GITHUB_REDIRECT_URI", "").strip(),
        authorize_url=os.getenv(
            "CMS_GITHUB_AUTHORIZE_URL",
            "https://github.com/login/oauth/authorize",
        ).strip(),
        token_url=os.getenv(
            "CMS_GITHUB_TOKEN_URL",
            "https://github.com/login/oauth/access_token",
        ).strip(),
        default_scope=os.getenv("CMS_GITHUB_SCOPE", "repo").strip() or "repo",
        state_ttl_seconds=max(60, int(os.getenv("CMS_OAUTH_STATE_TTL_SECONDS", "600"))),
    )


def _b64url_encode(raw_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=")


def _b64url_decode(raw_string: str) -> bytes:
    padding = "=" * (-len(raw_string) % 4)
    return base64.urlsafe_b64decode(raw_string + padding)


def sign_oauth_state(*, site_id: str, scope: str, secret: str) -> str:
    payload = {
        "site_id": site_id,
        "scope": scope,
        "iat": int(time.time()),
    }
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), payload_part.encode("utf-8"), hashlib.sha256)
    signature_part = _b64url_encode(signature.digest())
    return f"{payload_part}.{signature_part}"


def verify_oauth_state(*, state: str, secret: str, ttl_seconds: int) -> dict[str, str] | None:
    if not state or "." not in state:
        return None

    payload_part, signature_part = state.split(".", 1)
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        payload_part.encode("utf-8"),
        hashlib.sha256,
    )
    expected_signature_part = _b64url_encode(expected_signature.digest())

    if not hmac.compare_digest(signature_part, expected_signature_part):
        return None

    try:
        payload = json.loads(_b64url_decode(payload_part).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    issued_at = payload.get("iat")
    if not isinstance(issued_at, int):
        return None

    if int(time.time()) - issued_at > ttl_seconds:
        return None

    site_id = payload.get("site_id")
    scope = payload.get("scope")
    if not isinstance(site_id, str) or not isinstance(scope, str):
        return None

    return {"site_id": site_id, "scope": scope}


def render_popup_success(provider: str, payload: dict[str, str], app_base_url: str) -> str:
    payload_json = json.dumps(payload)
    dashboard_url = f"{app_base_url}#admin-dashboard"
    cms_url = f"{app_base_url}admin/"
    return f"""<!doctype html>
<html>
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
    <title>CMS Login Complete</title>
  </head>
  <body>
    <script>
      (function() {{
        var provider = {json.dumps(provider)};
        var success = 'authorization:' + provider + ':success:' + {json.dumps(payload_json)};

        function post(message) {{
          if (window.opener) {{
            window.opener.postMessage(message, '*');
          }}
        }}

        window.addEventListener('message', function(event) {{
          if (event.data === 'authorizing:' + provider) {{
            post(event.data);
            post(success);
            window.close();
          }}
        }});

        post('authorizing:' + provider);
      }})();
    </script>
    <main style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:1.25rem;\">
      <p style=\"margin:0 0 1rem;\">Authentication complete. You can close this window.</p>
      <nav style=\"display:flex;flex-wrap:wrap;gap:8px;\">
        <a href=\"{dashboard_url}\" style=\"padding:8px 12px;border-radius:10px;background:#18181b;color:#e4e4e7;border:1px solid #3f3f46;text-decoration:none;font:600 13px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\">Open Dashboard</a>
        <a href=\"{cms_url}\" style=\"padding:8px 12px;border-radius:10px;background:#18181b;color:#e4e4e7;border:1px solid #3f3f46;text-decoration:none;font:600 13px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\">Open CMS</a>
        <a href=\"{app_base_url}\" style=\"padding:8px 12px;border-radius:10px;background:#18181b;color:#e4e4e7;border:1px solid #3f3f46;text-decoration:none;font:600 13px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\">Back to Main Page</a>
      </nav>
    </main>
  </body>
</html>
"""


def render_popup_error(provider: str, message: str, app_base_url: str) -> str:
    payload_json = json.dumps({"message": message})
    dashboard_url = f"{app_base_url}#admin-dashboard"
    cms_url = f"{app_base_url}admin/"
    return f"""<!doctype html>
<html>
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
    <title>CMS Login Failed</title>
  </head>
  <body>
    <script>
      (function() {{
        var provider = {json.dumps(provider)};
        var failure = 'authorization:' + provider + ':error:' + {json.dumps(payload_json)};

        function post(message) {{
          if (window.opener) {{
            window.opener.postMessage(message, '*');
          }}
        }}

        window.addEventListener('message', function(event) {{
          if (event.data === 'authorizing:' + provider) {{
            post(event.data);
            post(failure);
            window.close();
          }}
        }});

        post('authorizing:' + provider);
      }})();
    </script>
    <main style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:1.25rem;\">
      <p style=\"margin:0 0 1rem;\">Authentication failed. You can close this window.</p>
      <nav style=\"display:flex;flex-wrap:wrap;gap:8px;\">
        <a href=\"{dashboard_url}\" style=\"padding:8px 12px;border-radius:10px;background:#18181b;color:#e4e4e7;border:1px solid #3f3f46;text-decoration:none;font:600 13px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\">Open Dashboard</a>
        <a href=\"{cms_url}\" style=\"padding:8px 12px;border-radius:10px;background:#18181b;color:#e4e4e7;border:1px solid #3f3f46;text-decoration:none;font:600 13px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\">Open CMS</a>
        <a href=\"{app_base_url}\" style=\"padding:8px 12px;border-radius:10px;background:#18181b;color:#e4e4e7;border:1px solid #3f3f46;text-decoration:none;font:600 13px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\">Back to Main Page</a>
      </nav>
    </main>
  </body>
</html>
"""
