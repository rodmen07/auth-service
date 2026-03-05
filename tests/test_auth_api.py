from fastapi.testclient import TestClient
import os

from app.main import app


def test_issue_and_verify_token_round_trip() -> None:
    client = TestClient(app)

    token_response = client.post(
        "/auth/token",
        json={"subject": "demo-user", "roles": ["user", "planner"]},
    )

    assert token_response.status_code == 200
    payload = token_response.json()
    assert payload["token_type"] == "bearer"
    assert payload["expires_in"] > 0
    assert payload["access_token"]

    verify_response = client.post(
        "/auth/verify",
        json={"token": payload["access_token"]},
    )

    assert verify_response.status_code == 200
    verified = verify_response.json()
    assert verified["active"] is True
    assert verified["subject"] == "demo-user"
    assert verified["roles"] == ["user", "planner"]


def test_verify_invalid_token_returns_inactive() -> None:
    client = TestClient(app)

    verify_response = client.post(
        "/auth/verify",
        json={"token": "not-a-real-token"},
    )

    assert verify_response.status_code == 200
    payload = verify_response.json()
    assert payload["active"] is False


def test_issue_token_rejects_privileged_role_for_non_admin_subject() -> None:
    unsafe_previous = os.getenv("AUTH_ADMIN_SUBJECTS")
    os.environ["AUTH_ADMIN_SUBJECTS"] = "admin-user"

    try:
        client = TestClient(app)
        response = client.post(
            "/auth/token",
            json={"subject": "regular-user", "roles": ["admin"]},
        )

        assert response.status_code == 403
    finally:
        if unsafe_previous is None:
            os.environ.pop("AUTH_ADMIN_SUBJECTS", None)
        else:
            os.environ["AUTH_ADMIN_SUBJECTS"] = unsafe_previous


def test_issue_token_allows_privileged_role_for_admin_subject() -> None:
    unsafe_previous = os.getenv("AUTH_ADMIN_SUBJECTS")
    os.environ["AUTH_ADMIN_SUBJECTS"] = "admin-user"

    try:
        client = TestClient(app)
        token_response = client.post(
            "/auth/token",
            json={"subject": "admin-user", "roles": ["admin", "ADMIN", "user"]},
        )

        assert token_response.status_code == 200
        payload = token_response.json()

        verify_response = client.post(
            "/auth/verify",
            json={"token": payload["access_token"]},
        )

        assert verify_response.status_code == 200
        verified = verify_response.json()
        assert verified["active"] is True
        assert verified["roles"] == ["admin", "user"]
    finally:
        if unsafe_previous is None:
            os.environ.pop("AUTH_ADMIN_SUBJECTS", None)
        else:
            os.environ["AUTH_ADMIN_SUBJECTS"] = unsafe_previous


def test_revoke_token_makes_verify_return_inactive() -> None:
    client = TestClient(app)

    # Issue a token.
    token_resp = client.post(
        "/auth/token",
        json={"subject": "rev-user", "roles": ["user"]},
    )
    assert token_resp.status_code == 200
    access_token = token_resp.json()["access_token"]

    # Verify it's active before revocation.
    verify_resp = client.post("/auth/verify", json={"token": access_token})
    assert verify_resp.json()["active"] is True

    # Revoke.
    revoke_resp = client.post("/auth/revoke", json={"token": access_token})
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["revoked"] is True

    # Verify it's now inactive.
    verify_resp = client.post("/auth/verify", json={"token": access_token})
    assert verify_resp.json()["active"] is False
