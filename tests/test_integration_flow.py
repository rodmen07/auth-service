"""Integration tests covering the full authentication lifecycle:

  register → login → refresh (token rotation) → old-token replay rejected
  → access token revocation → logout

Uses FastAPI TestClient (in-process ASGI) backed by an isolated per-test
SQLite database via the DATABASE_URL env var.
"""
import os

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh TestClient backed by a temporary SQLite database."""
    db = tmp_path / "test_auth.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    # Disable invite enforcement so open registration works in tests.
    monkeypatch.delenv("REQUIRE_INVITE", raising=False)
    # Ensure a stable HMAC secret is in place.
    monkeypatch.setenv("AUTH_JWT_SECRET", "test-integration-secret-32chars!!")
    monkeypatch.setenv("AUTH_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("AUTH_ISSUER", "auth-service")

    # Import app after env vars are patched so config is picked up.
    from app.main import app  # noqa: PLC0415 (import inside function is intentional)
    from app.rate_limit import limiter  # noqa: PLC0415
    # Use the context-manager form so FastAPI lifespan runs (which calls init_db).
    with TestClient(app, raise_server_exceptions=True) as c:
        # Clear any carry-over rate-limit state from previous tests.
        limiter.clear()
        yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_EMAIL = "integration@example.com"
_TEST_PASS = "S3cret!Integration"


def _register(client: TestClient) -> dict:
    r = client.post("/auth/register", json={"username": _TEST_EMAIL, "password": _TEST_PASS})
    assert r.status_code == 201, r.text
    return r


def _login(client: TestClient) -> tuple[str, str]:
    r = client.post("/auth/login", json={"username": _TEST_EMAIL, "password": _TEST_PASS})
    assert r.status_code == 200, r.text
    access_token = r.json()["access_token"]
    refresh_cookie = r.cookies.get("refresh_token")
    assert refresh_cookie, "Expected refresh_token cookie after login"
    return access_token, refresh_cookie


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRegisterLogin:
    def test_register_returns_201_with_access_token(self, client):
        r = _register(client)
        data = r.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert r.cookies.get("refresh_token")

    def test_duplicate_registration_returns_409(self, client):
        _register(client)
        r = client.post("/auth/register", json={"username": _TEST_EMAIL, "password": _TEST_PASS})
        assert r.status_code == 409

    def test_login_returns_access_and_refresh_token(self, client):
        _register(client)
        access, refresh = _login(client)
        assert access
        assert refresh

    def test_login_wrong_password_returns_401(self, client):
        _register(client)
        r = client.post("/auth/login", json={"username": _TEST_EMAIL, "password": "wrong"})
        assert r.status_code == 401

    def test_access_token_verifies_as_active(self, client):
        _register(client)
        access, _ = _login(client)
        r = client.post("/auth/verify", json={"token": access})
        assert r.status_code == 200
        data = r.json()
        assert data["active"] is True
        # The JWT subject is the user's internal UUID, not the e-mail address.
        assert data["subject"]


class TestRefreshTokenRotation:
    def test_refresh_issues_new_access_token(self, client):
        _register(client)
        _, refresh = _login(client)
        r = client.post("/auth/refresh", cookies={"refresh_token": refresh})
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_refresh_rotates_cookie(self, client):
        _register(client)
        _, original_refresh = _login(client)
        r = client.post("/auth/refresh", cookies={"refresh_token": original_refresh})
        assert r.status_code == 200
        new_refresh = r.cookies.get("refresh_token")
        assert new_refresh, "Expected a new refresh_token cookie after rotation"
        assert new_refresh != original_refresh, "Refresh token must change on rotation"

    def test_replayed_refresh_token_is_rejected(self, client):
        """Reusing the old refresh token after rotation must return 401."""
        _register(client)
        _, original_refresh = _login(client)
        # First refresh — rotates the token
        client.post("/auth/refresh", cookies={"refresh_token": original_refresh})
        # Second use of the same token — must fail
        r = client.post("/auth/refresh", cookies={"refresh_token": original_refresh})
        assert r.status_code == 401

    def test_new_refresh_token_works_after_rotation(self, client):
        _register(client)
        _, original_refresh = _login(client)
        r1 = client.post("/auth/refresh", cookies={"refresh_token": original_refresh})
        new_refresh = r1.cookies.get("refresh_token")
        assert new_refresh
        r2 = client.post("/auth/refresh", cookies={"refresh_token": new_refresh})
        assert r2.status_code == 200

    def test_refresh_without_cookie_returns_401(self, client):
        r = client.post("/auth/refresh")
        assert r.status_code == 401


class TestTokenRevocation:
    def test_revoke_then_verify_returns_inactive(self, client):
        _register(client)
        access, _ = _login(client)
        r = client.post("/auth/revoke", json={"token": access})
        assert r.status_code == 200
        assert r.json()["revoked"] is True
        r2 = client.post("/auth/verify", json={"token": access})
        assert r2.json()["active"] is False

    def test_revoke_invalid_token_returns_400(self, client):
        r = client.post("/auth/revoke", json={"token": "not-a-jwt"})
        assert r.status_code == 400


class TestLogout:
    def test_logout_invalidates_refresh_token(self, client):
        _register(client)
        _, refresh = _login(client)
        r = client.post("/auth/logout", cookies={"refresh_token": refresh})
        assert r.status_code == 204
        # Refresh after logout must fail
        r2 = client.post("/auth/refresh", cookies={"refresh_token": refresh})
        assert r2.status_code == 401


class TestJWKSEndpoint:
    def test_jwks_returns_200_with_keys_array(self, client):
        r = client.get("/.well-known/jwks.json")
        assert r.status_code == 200
        data = r.json()
        assert "keys" in data
        assert isinstance(data["keys"], list)

    def test_jwks_returns_empty_keys_for_hs256(self, client):
        """HS256 must not expose the symmetric secret in the JWKS response."""
        r = client.get("/.well-known/jwks.json")
        assert r.json()["keys"] == []
