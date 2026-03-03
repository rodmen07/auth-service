from fastapi.testclient import TestClient

from app.cms_oauth import sign_oauth_state, verify_oauth_state
from app.main import app


def test_sign_and_verify_state_round_trip() -> None:
    state = sign_oauth_state(site_id="rodmen07.github.io", scope="repo", secret="test-secret")

    payload = verify_oauth_state(
        state=state,
        secret="test-secret",
        ttl_seconds=600,
    )

    assert payload is not None
    assert payload["site_id"] == "rodmen07.github.io"
    assert payload["scope"] == "repo"


def test_verify_state_rejects_tampered_signature() -> None:
    state = sign_oauth_state(site_id="rodmen07.github.io", scope="repo", secret="test-secret")
    tampered = f"{state}x"

    payload = verify_oauth_state(
        state=tampered,
        secret="test-secret",
        ttl_seconds=600,
    )

    assert payload is None


def test_cms_auth_redirects_when_oauth_not_configured() -> None:
    client = TestClient(app)

    response = client.get(
        "/cms/auth",
        params={"provider": "github", "site_id": "rodmen07.github.io"},
        follow_redirects=False,
    )

    assert response.status_code in {302, 307}
    assert "oauth_not_configured" in response.headers["location"]


def test_cms_callback_missing_params_returns_popup_error() -> None:
    client = TestClient(app)

    response = client.get("/cms/callback")

    assert response.status_code == 400
    assert "CMS Login Failed" in response.text
    assert "authorization:" in response.text
