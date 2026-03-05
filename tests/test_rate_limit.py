"""Tests for the in-memory IP-based rate limiter."""

from app.rate_limit import RateLimiter


def test_allows_up_to_max_requests():
    rl = RateLimiter(max_requests=3, window_seconds=60)
    assert rl.is_allowed("1.2.3.4") is True
    assert rl.is_allowed("1.2.3.4") is True
    assert rl.is_allowed("1.2.3.4") is True
    assert rl.is_allowed("1.2.3.4") is False


def test_different_ips_have_independent_limits():
    rl = RateLimiter(max_requests=2, window_seconds=60)
    assert rl.is_allowed("10.0.0.1") is True
    assert rl.is_allowed("10.0.0.1") is True
    assert rl.is_allowed("10.0.0.1") is False
    # Different IP should still be allowed
    assert rl.is_allowed("10.0.0.2") is True


def test_remaining_reflects_usage():
    rl = RateLimiter(max_requests=5, window_seconds=60)
    assert rl.remaining("9.9.9.9") == 5
    rl.is_allowed("9.9.9.9")
    rl.is_allowed("9.9.9.9")
    assert rl.remaining("9.9.9.9") == 3


def test_token_endpoint_returns_429_when_rate_limited():
    """Integration test: hit /auth/token beyond the limit and expect 429."""
    from fastapi.testclient import TestClient
    from app.rate_limit import limiter
    from app.main import app

    # Temporarily set a very low limit for testing
    original_max = limiter.max_requests
    original_window = limiter.window_seconds
    limiter.max_requests = 2
    limiter.window_seconds = 60
    limiter._buckets.clear()

    client = TestClient(app)
    payload = {"subject": "flood-test", "roles": ["user"]}

    try:
        r1 = client.post("/auth/token", json=payload)
        assert r1.status_code == 200

        r2 = client.post("/auth/token", json=payload)
        assert r2.status_code == 200

        r3 = client.post("/auth/token", json=payload)
        assert r3.status_code == 429
        assert "retry_after_seconds" in r3.json()
        assert "Retry-After" in r3.headers
    finally:
        limiter.max_requests = original_max
        limiter.window_seconds = original_window
        limiter._buckets.clear()
