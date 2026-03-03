from fastapi.testclient import TestClient

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
