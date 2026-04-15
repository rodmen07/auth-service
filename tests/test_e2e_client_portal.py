"""End-to-end test: crew-assist client portal onboarding flow.

Scenario: Ryan (ryanchylerthomas) is a freelance client hired for the crew-assist project.
The admin invites him via email link, he registers, logs in with refresh cookie, refreshes
his access token, logs out, and resets his password. This mirrors the real onboarding flow
for the crew-assist test case.
"""

import os
import tempfile
import unittest.mock

# ── DB isolation: must happen before any app.* import ───────────────────────
_db_file = tempfile.NamedTemporaryFile(suffix="-e2e-portal.db", delete=False)
os.environ["DATABASE_URL"] = f"sqlite:///{_db_file.name}"

# Allow a predictable admin subject for /auth/token
os.environ["AUTH_ADMIN_SUBJECTS"] = "admin-e2e-subject"

# Suppress real email sending
os.environ["SMTP_HOST"] = ""

os.environ["RATE_LIMIT_MAX_REQUESTS"] = "1000"

import pytest
from fastapi.testclient import TestClient

from app.main import app  # noqa: E402 — must come after env setup


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token(client):
    """Issue an admin JWT via /auth/token (service-to-service endpoint)."""
    resp = client.post(
        "/auth/token",
        json={"subject": "admin-e2e-subject", "roles": ["admin"]},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ── Helpers ──────────────────────────────────────────────────────────────────

def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Tests ────────────────────────────────────────────────────────────────────


class TestHealth:
    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestAdminInviteFlow:
    """Admin invites Ryan; Ryan registers and receives a client JWT."""

    # Shared state across test methods in this class
    _invite_token: str = ""
    _ryan_access_token: str = ""

    def test_invite_requires_auth(self, client):
        resp = client.post("/auth/invite", json={"email": "ryan@crewassist-test.example"})
        assert resp.status_code == 401

    def test_invite_requires_admin_role(self, client):
        # Issue a non-admin token and try to invite
        non_admin = client.post(
            "/auth/token", json={"subject": "basic-user", "roles": ["user"]}
        ).json()["access_token"]
        resp = client.post(
            "/auth/invite",
            json={"email": "ryan@crewassist-test.example"},
            headers=auth_headers(non_admin),
        )
        assert resp.status_code == 403

    def test_admin_can_create_invite(self, client, admin_token):
        with unittest.mock.patch("app.main.send_invite_email") as mock_send:
            mock_send.return_value = None
            resp = client.post(
                "/auth/invite",
                json={"email": "ryan@crewassist-test.example"},
                headers=auth_headers(admin_token),
            )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["email"] == "ryan@crewassist-test.example"
        assert "token=" in body["invite_url"]
        # Store the raw token from the URL for later registration
        TestAdminInviteFlow._invite_token = body["invite_url"].split("token=", 1)[1]

    def test_register_without_token_succeeds_with_default_roles(self, client):
        """Registration without invite is allowed — user gets default roles (not client)."""
        resp = client.post(
            "/auth/register",
            json={"username": "norole@crewassist-test.example", "password": "SomePass99!"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert "client" not in body["roles"]  # no invite → no client role

    def test_register_with_bad_token_fails(self, client):
        resp = client.post(
            "/auth/register?token=not-a-real-token",
            json={"username": "badinvite@crewassist-test.example", "password": "TestPass123!"},
        )
        assert resp.status_code == 400

    def test_ryan_registers_with_invite(self, client):
        assert TestAdminInviteFlow._invite_token, "invite token not set"
        resp = client.post(
            f"/auth/register?token={TestAdminInviteFlow._invite_token}",
            json={"username": "ryan@crewassist-test.example", "password": "TestPass123!"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "access_token" in body
        assert "client" in body["roles"]
        TestAdminInviteFlow._ryan_access_token = body["access_token"]

    def test_invite_token_is_single_use(self, client):
        resp = client.post(
            f"/auth/register?token={TestAdminInviteFlow._invite_token}",
            json={"username": "other@crewassist-test.example", "password": "AnotherPass!"},
        )
        assert resp.status_code == 400


class TestLoginAndRefreshFlow:
    """Ryan logs in with email+password, gets refresh cookie, refreshes token, logs out."""

    _access_token: str = ""
    _refresh_cookie: str = ""

    def test_login_with_wrong_password_fails(self, client):
        resp = client.post(
            "/auth/login",
            json={"username": "ryan@crewassist-test.example", "password": "WrongPassword!"},
        )
        assert resp.status_code == 401

    def test_login_succeeds(self, client):
        resp = client.post(
            "/auth/login",
            json={"username": "ryan@crewassist-test.example", "password": "TestPass123!"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "access_token" in body
        assert "client" in body["roles"]
        # Refresh cookie must be set
        assert "refresh_token" in resp.cookies
        TestLoginAndRefreshFlow._access_token = body["access_token"]
        TestLoginAndRefreshFlow._refresh_cookie = resp.cookies["refresh_token"]

    def test_access_token_is_valid(self, client):
        token = TestLoginAndRefreshFlow._access_token
        resp = client.post("/auth/verify", json={"token": token})
        assert resp.status_code == 200
        body = resp.json()
        assert body["active"] is True
        assert "client" in (body.get("roles") or [])

    def test_refresh_issues_new_access_token(self, client):
        cookie = TestLoginAndRefreshFlow._refresh_cookie
        resp = client.post("/auth/refresh", cookies={"refresh_token": cookie})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "access_token" in body
        # Store refreshed token for next check
        TestLoginAndRefreshFlow._access_token = body["access_token"]

    def test_refresh_with_invalid_cookie_fails(self, client):
        resp = client.post("/auth/refresh", cookies={"refresh_token": "garbage-token-value"})
        assert resp.status_code == 401

    def test_logout_clears_session(self, client):
        cookie = TestLoginAndRefreshFlow._refresh_cookie
        resp = client.post("/auth/logout", cookies={"refresh_token": cookie})
        assert resp.status_code == 204
        # After logout, old refresh cookie no longer works
        resp2 = client.post("/auth/refresh", cookies={"refresh_token": cookie})
        assert resp2.status_code == 401


class TestPasswordReset:
    """Ryan resets his password via email link."""

    _reset_token: str = ""

    def test_reset_request_always_returns_202(self, client):
        """Anti-enumeration: always returns 202 even for unregistered email."""
        with unittest.mock.patch("app.main.send_password_reset_email") as mock_send:
            mock_send.return_value = None

            # Registered email
            resp1 = client.post(
                "/auth/password/reset-request",
                json={"email": "ryan@crewassist-test.example"},
            )
            assert resp1.status_code == 202

            # Unregistered email — must also return 202 (no enumeration)
            resp2 = client.post(
                "/auth/password/reset-request",
                json={"email": "nobody@does-not-exist.example"},
            )
            assert resp2.status_code == 202

    def test_reset_request_issues_token(self, client):
        """Capture the raw token issued internally to use in the confirm step."""
        captured: list[str] = []

        async def fake_send(email: str, url: str) -> None:
            token = url.split("token=", 1)[1] if "token=" in url else ""
            captured.append(token)

        with unittest.mock.patch("app.main.send_password_reset_email", new=fake_send):
            resp = client.post(
                "/auth/password/reset-request",
                json={"email": "ryan@crewassist-test.example"},
            )
        assert resp.status_code == 202
        assert captured, "reset email was not called for registered user"
        TestPasswordReset._reset_token = captured[0]

    def test_reset_with_bad_token_fails(self, client):
        resp = client.post(
            "/auth/password/reset",
            json={"token": "not-a-real-token", "password": "NewPass123!"},
        )
        assert resp.status_code == 400

    def test_reset_confirms_and_allows_login_with_new_password(self, client):
        token = TestPasswordReset._reset_token
        assert token, "reset token not captured"

        # Confirm reset
        resp = client.post(
            "/auth/password/reset",
            json={"token": token, "password": "NewPass456!"},
        )
        assert resp.status_code == 200, resp.text

        # Old password no longer works — use a distinct IP to avoid rate limit from prior login tests
        resp_old = client.post(
            "/auth/login",
            json={"username": "ryan@crewassist-test.example", "password": "TestPass123!"},
            headers={"X-Forwarded-For": "10.0.0.100"},
        )
        assert resp_old.status_code == 401

        # New password works
        resp_new = client.post(
            "/auth/login",
            json={"username": "ryan@crewassist-test.example", "password": "NewPass456!"},
            headers={"X-Forwarded-For": "10.0.0.100"},
        )
        assert resp_new.status_code == 200
        assert "access_token" in resp_new.json()

    def test_reset_token_is_single_use(self, client):
        token = TestPasswordReset._reset_token
        resp = client.post(
            "/auth/password/reset",
            json={"token": token, "password": "AttemptThree!"},
        )
        assert resp.status_code == 400
