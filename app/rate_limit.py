"""In-memory sliding-window rate limiter keyed by client IP.

Limits are enforced per-IP and reset after the configured window elapses.
This is intentionally simple (no Redis dependency) and suitable for a
single-instance deployment on Fly.io.
"""

import os
import time
import threading
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    """Tracks request timestamps for a single IP within the current window."""
    timestamps: list[float] = field(default_factory=list)


class RateLimiter:
    """Thread-safe sliding-window rate limiter.

    Parameters
    ----------
    max_requests : int
        Maximum number of requests allowed per window.
    window_seconds : int
        Length of the sliding window in seconds.
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        """Return True if the request should be allowed, False if rate-limited."""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket()
                self._buckets[key] = bucket

            # Evict timestamps outside the window
            bucket.timestamps = [ts for ts in bucket.timestamps if ts > cutoff]

            if len(bucket.timestamps) >= self.max_requests:
                return False

            bucket.timestamps.append(now)
            return True

    def remaining(self, key: str) -> int:
        """Return how many requests remain in the current window for *key*."""
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return self.max_requests
            active = [ts for ts in bucket.timestamps if ts > cutoff]
            return max(0, self.max_requests - len(active))


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    try:
        return int(raw)
    except (ValueError, TypeError):
        return default


# Global limiter instance — configured from env at import time.
# RATE_LIMIT_MAX_REQUESTS: max calls per window per IP  (default 20)
# RATE_LIMIT_WINDOW_SECONDS: sliding window length       (default 60)
_max_requests = _env_int("RATE_LIMIT_MAX_REQUESTS", 20)
_window_seconds = _env_int("RATE_LIMIT_WINDOW_SECONDS", 60)

limiter = RateLimiter(max_requests=_max_requests, window_seconds=_window_seconds)
