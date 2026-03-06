"""
Tests for the new user password auth endpoints:
  POST /auth/register
  POST /auth/login

These tests use an in-memory (temporary) SQLite database so they do not affect
any persistent auth.db file on disk.
"""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# Point DATABASE_URL to a temp file before importing the app so that
# init_db writes to a throw-away database, not the real one.
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"

from app.main import app  # noqa: E402  (must come after env var is set)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# /auth/register
# ---------------------------------------------------------------------------

def test_register_creates_user_and_returns_token(client):
    resp = client.post("/auth/register", json={"username": "alice@example.com", "password": "hunter22!"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    assert body["access_token"]
    assert body["username"] == "alice@example.com"
    assert "user_id" in body
    assert "user" in body["roles"]


def test_register_duplicate_username_returns_409(client):
    client.post("/auth/register", json={"username": "bob@example.com", "password": "password1"})
    resp = client.post("/auth/register", json={"username": "bob@example.com", "password": "different99"})
    assert resp.status_code == 409


def test_register_rejects_short_password(client):
    resp = client.post("/auth/register", json={"username": "carol@example.com", "password": "ab"})
    assert resp.status_code == 422


def test_register_rejects_invalid_username_chars(client):
    resp = client.post("/auth/register", json={"username": "not-an-email", "password": "longpassword1"})
    assert resp.status_code == 422


def test_register_rejects_short_username(client):
    resp = client.post("/auth/register", json={"username": "a@b.c", "password": "longpassword1"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /auth/login
# ---------------------------------------------------------------------------

def test_login_with_correct_password_returns_token(client):
    client.post("/auth/register", json={"username": "dave@example.com", "password": "correct_horse!"})

    resp = client.post("/auth/login", json={"username": "dave@example.com", "password": "correct_horse!"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["username"] == "dave@example.com"
    assert "user_id" in body


def test_login_with_wrong_password_returns_401(client):
    client.post("/auth/register", json={"username": "eve@example.com", "password": "correct_horse!"})

    resp = client.post("/auth/login", json={"username": "eve@example.com", "password": "wrong_password"})
    assert resp.status_code == 401
    # Should not leak info about whether the user exists
    assert "Invalid" in resp.json()["detail"]


def test_login_unknown_user_returns_401(client):
    resp = client.post("/auth/login", json={"username": "nobody@example.com", "password": "any_password"})
    assert resp.status_code == 401


def test_login_issues_verifiable_jwt(client):
    client.post("/auth/register", json={"username": "frank@example.com", "password": "verifytest1"})
    login_resp = client.post("/auth/login", json={"username": "frank@example.com", "password": "verifytest1"})
    token = login_resp.json()["access_token"]

    verify_resp = client.post("/auth/verify", json={"token": token})
    assert verify_resp.status_code == 200
    verified = verify_resp.json()
    assert verified["active"] is True
    # sub should be the UUID (not the email)
    assert verified["subject"] != "frank@example.com"
    assert len(verified["subject"]) == 36  # UUID v4 format


# ---------------------------------------------------------------------------
# Admin role gating
# ---------------------------------------------------------------------------

def test_admin_role_granted_when_username_in_admin_subjects(client):
    prev = os.getenv("AUTH_ADMIN_SUBJECTS")
    os.environ["AUTH_ADMIN_SUBJECTS"] = "grace@example.com"

    try:
        client.post("/auth/register", json={"username": "grace@example.com", "password": "adminpassword1"})
        resp = client.post("/auth/login", json={"username": "grace@example.com", "password": "adminpassword1"})
        assert resp.status_code == 200
        assert "admin" in resp.json()["roles"]
    finally:
        if prev is None:
            os.environ.pop("AUTH_ADMIN_SUBJECTS", None)
        else:
            os.environ["AUTH_ADMIN_SUBJECTS"] = prev


def test_admin_role_not_granted_for_normal_user(client):
    prev = os.getenv("AUTH_ADMIN_SUBJECTS")
    os.environ["AUTH_ADMIN_SUBJECTS"] = "grace@example.com"  # only grace is admin

    try:
        client.post("/auth/register", json={"username": "heidi@example.com", "password": "normalpassword1"})
        resp = client.post("/auth/login", json={"username": "heidi@example.com", "password": "normalpassword1"})
        assert resp.status_code == 200
        assert "admin" not in resp.json()["roles"]
    finally:
        if prev is None:
            os.environ.pop("AUTH_ADMIN_SUBJECTS", None)
        else:
            os.environ["AUTH_ADMIN_SUBJECTS"] = prev
