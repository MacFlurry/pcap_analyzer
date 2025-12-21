"""
Simple in-memory rate limiter for authentication endpoints.

Security:
- Prevents brute force attacks (OWASP ASVS V2.2.1)
- Implements exponential backoff
- Tracks failed attempts per IP address

Note: This is a basic implementation suitable for small deployments.
For production at scale, consider Redis-based rate limiting.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class RateLimitState:
    """Track rate limit state for a client."""
    failed_attempts: int = 0
    last_attempt_time: float = 0.0
    lockout_until: float = 0.0


class RateLimiter:
    """
    Simple in-memory rate limiter.

    Implements exponential backoff for failed login attempts:
    - 1st failure: No delay
    - 2nd failure: No delay
    - 3rd failure: No delay
    - 4th failure: 1 second lockout
    - 5th failure: 2 seconds lockout
    - 6th+ failure: 5 seconds lockout

    Resets on successful login.
    """

    def __init__(self):
        self.states: Dict[str, RateLimitState] = defaultdict(RateLimitState)
        self._cleanup_interval = 3600  # Clean up old entries every hour
        self._last_cleanup = time.time()

    def _cleanup_old_entries(self):
        """Remove entries older than 1 hour to prevent memory leak."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        # Remove entries with no recent activity (1 hour)
        stale_keys = [
            key for key, state in self.states.items()
            if now - state.last_attempt_time > 3600
        ]
        for key in stale_keys:
            del self.states[key]

        self._last_cleanup = now
        if stale_keys:
            logger.debug(f"Rate limiter cleaned up {len(stale_keys)} stale entries")

    def is_allowed(self, client_id: str) -> tuple[bool, Optional[float]]:
        """
        Check if client is allowed to attempt login.

        Args:
            client_id: Client identifier (e.g., IP address or username)

        Returns:
            (allowed, retry_after_seconds)
            - allowed: True if login attempt is allowed
            - retry_after_seconds: None if allowed, or seconds until next attempt
        """
        self._cleanup_old_entries()

        state = self.states[client_id]
        now = time.time()

        # Check if client is locked out
        if state.lockout_until > now:
            retry_after = state.lockout_until - now
            logger.warning(f"Rate limit: Client {client_id} is locked out (retry after {retry_after:.1f}s)")
            return False, retry_after

        return True, None

    def record_failure(self, client_id: str):
        """
        Record failed login attempt and apply lockout if needed.

        Args:
            client_id: Client identifier
        """
        state = self.states[client_id]
        state.failed_attempts += 1
        state.last_attempt_time = time.time()

        # Exponential backoff
        if state.failed_attempts == 4:
            state.lockout_until = time.time() + 1  # 1 second
            logger.warning(f"Rate limit: Client {client_id} locked out for 1s (4 failed attempts)")
        elif state.failed_attempts == 5:
            state.lockout_until = time.time() + 2  # 2 seconds
            logger.warning(f"Rate limit: Client {client_id} locked out for 2s (5 failed attempts)")
        elif state.failed_attempts >= 6:
            state.lockout_until = time.time() + 5  # 5 seconds
            logger.warning(f"Rate limit: Client {client_id} locked out for 5s ({state.failed_attempts} failed attempts)")

    def record_success(self, client_id: str):
        """
        Record successful login and reset failed attempts counter.

        Args:
            client_id: Client identifier
        """
        if client_id in self.states:
            del self.states[client_id]
            logger.debug(f"Rate limit: Client {client_id} counter reset (successful login)")


# Global singleton instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get singleton rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter
