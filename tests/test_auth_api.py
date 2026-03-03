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
