"""File-backed sliding-window rate limiter keyed by client IP.

Limits are enforced per-IP and reset after the configured window elapses.
State is periodically flushed to disk so that limits survive restarts.
If the state file is unavailable, the limiter degrades to pure in-memory.
"""

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class _Bucket:
    """Tracks request timestamps for a single IP within the current window."""
    timestamps: list[float] = field(default_factory=list)


class RateLimiter:
    """Thread-safe sliding-window rate limiter with optional file persistence.

    Parameters
    ----------
    max_requests : int
        Maximum number of requests allowed per window.
    window_seconds : int
        Length of the sliding window in seconds.
    state_file : str
        Path to a JSON file for persisting state across restarts.
        Empty string disables persistence.
    flush_interval : int
        Seconds between automatic background flushes (0 = disabled).
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        state_file: str = "",
        flush_interval: int = 30,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._state_file = state_file
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._dirty = False

        # Try to restore from disk.
        if self._state_file:
            self._load_state()

        # Periodically flush to disk.
        if self._state_file and flush_interval > 0:
            self._flush_timer = threading.Timer(flush_interval, self._periodic_flush, args=(flush_interval,))
            self._flush_timer.daemon = True
            self._flush_timer.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_allowed(self, key: str) -> bool:
        """Return True if the request should be allowed, False if rate-limited."""
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket()
                self._buckets[key] = bucket

            bucket.timestamps = [ts for ts in bucket.timestamps if ts > cutoff]

            if len(bucket.timestamps) >= self.max_requests:
                return False

            bucket.timestamps.append(now)
            self._dirty = True
            return True

    def remaining(self, key: str) -> int:
        """Return how many requests remain in the current window for *key*."""
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return self.max_requests
            active = [ts for ts in bucket.timestamps if ts > cutoff]
            return max(0, self.max_requests - len(active))

    def flush(self) -> None:
        """Write current state to disk (no-op if persistence is disabled)."""
        if not self._state_file:
            return
        self._save_state()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _save_state(self) -> None:
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            if not self._dirty:
                return
            data: dict[str, list[float]] = {}
            for key, bucket in self._buckets.items():
                active = [ts for ts in bucket.timestamps if ts > cutoff]
                if active:
                    data[key] = active
            self._dirty = False

        try:
            path = Path(self._state_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            logger.debug("rate-limit: could not write state file %s", self._state_file)

    def _load_state(self) -> None:
        try:
            raw = Path(self._state_file).read_text(encoding="utf-8")
            data: dict[str, list[float]] = json.loads(raw)
        except (OSError, json.JSONDecodeError, ValueError):
            logger.debug("rate-limit: no existing state file at %s", self._state_file)
            return

        now = time.time()
        cutoff = now - self.window_seconds
        loaded = 0

        with self._lock:
            for key, timestamps in data.items():
                active = [ts for ts in timestamps if ts > cutoff]
                if active:
                    self._buckets[key] = _Bucket(timestamps=active)
                    loaded += 1

        if loaded:
            logger.info("rate-limit: restored %d IP buckets from %s", loaded, self._state_file)

    def _periodic_flush(self, interval: int) -> None:
        self._save_state()
        self._flush_timer = threading.Timer(interval, self._periodic_flush, args=(interval,))
        self._flush_timer.daemon = True
        self._flush_timer.start()


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "")
    try:
        return int(raw)
    except (ValueError, TypeError):
        return default


# Global limiter instance — configured from env at import time.
# RATE_LIMIT_MAX_REQUESTS:   max calls per window per IP  (default 20)
# RATE_LIMIT_WINDOW_SECONDS: sliding window length       (default 60)
# RATE_LIMIT_STATE_FILE:     path for persistence        (default "" = disabled)
_max_requests = _env_int("RATE_LIMIT_MAX_REQUESTS", 20)
_window_seconds = _env_int("RATE_LIMIT_WINDOW_SECONDS", 60)
_state_file = os.getenv("RATE_LIMIT_STATE_FILE", "")

limiter = RateLimiter(
    max_requests=_max_requests,
    window_seconds=_window_seconds,
    state_file=_state_file,
)
