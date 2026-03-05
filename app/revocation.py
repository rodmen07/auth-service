"""In-memory token revocation blocklist.

Revoked tokens are tracked by their JTI (JWT ID) claim.  The blocklist
automatically evicts entries once their corresponding token would have
expired, keeping memory usage bounded.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class _Entry:
    jti: str
    expires_at: float  # UTC epoch


@dataclass
class RevocationBlocklist:
    """Thread-safe set of revoked JTI values with automatic expiry."""

    _entries: dict[str, _Entry] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def revoke(self, jti: str, token_exp: int) -> None:
        """Add *jti* to the blocklist.  *token_exp* is the ``exp`` claim
        (UTC epoch seconds) so the entry can be evicted post-expiry."""
        with self._lock:
            self._entries[jti] = _Entry(jti=jti, expires_at=float(token_exp))

    def is_revoked(self, jti: str) -> bool:
        """Return ``True`` if *jti* has been revoked and has not yet expired."""
        with self._lock:
            entry = self._entries.get(jti)
            if entry is None:
                return False
            if time.time() > entry.expires_at:
                del self._entries[jti]
                return False
            return True

    def cleanup(self) -> int:
        """Remove all expired entries and return the number removed."""
        now = time.time()
        with self._lock:
            expired = [jti for jti, e in self._entries.items() if now > e.expires_at]
            for jti in expired:
                del self._entries[jti]
            return len(expired)


# Module-level singleton shared by the application.
blocklist = RevocationBlocklist()
