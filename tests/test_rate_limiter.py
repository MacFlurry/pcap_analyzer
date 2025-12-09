"""
Tests for SSH capture rate limiter.

These tests verify that the rate limiter correctly prevents brute force attacks
while allowing legitimate connection attempts.
"""

import pytest
import time
from src.ssh_capture import SSHCaptureRateLimiter, SSHCaptureError


class TestSSHCaptureRateLimiter:
    """Tests for SSHCaptureRateLimiter."""

    def test_initialization(self):
        """Test that rate limiter initializes with correct defaults."""
        limiter = SSHCaptureRateLimiter()
        assert limiter.max_attempts == 3
        assert limiter.window == 60
        assert limiter.attempts == []

    def test_custom_initialization(self):
        """Test that rate limiter accepts custom parameters."""
        limiter = SSHCaptureRateLimiter(max_attempts=5, window=120)
        assert limiter.max_attempts == 5
        assert limiter.window == 120

    def test_first_attempts_allowed(self):
        """Test that initial attempts are allowed."""
        limiter = SSHCaptureRateLimiter(max_attempts=3, window=60)

        # First 3 attempts should succeed
        assert limiter.check_and_record() is True
        assert limiter.check_and_record() is True
        assert limiter.check_and_record() is True

    def test_rate_limit_exceeded(self):
        """Test that rate limit is enforced after max attempts."""
        limiter = SSHCaptureRateLimiter(max_attempts=3, window=60)

        # First 3 attempts should succeed
        limiter.check_and_record()
        limiter.check_and_record()
        limiter.check_and_record()

        # Fourth attempt should raise error
        with pytest.raises(SSHCaptureError, match="Rate limit exceeded"):
            limiter.check_and_record()

    def test_rate_limit_resets_after_window(self):
        """Test that rate limit resets after the time window."""
        limiter = SSHCaptureRateLimiter(max_attempts=2, window=1)  # 1 second window

        # First 2 attempts
        limiter.check_and_record()
        limiter.check_and_record()

        # Third attempt should fail
        with pytest.raises(SSHCaptureError):
            limiter.check_and_record()

        # Wait for window to expire
        time.sleep(1.1)

        # Should be able to attempt again
        assert limiter.check_and_record() is True

    def test_manual_reset(self):
        """Test that manual reset clears attempts."""
        limiter = SSHCaptureRateLimiter(max_attempts=2, window=60)

        # Use up attempts
        limiter.check_and_record()
        limiter.check_and_record()

        # Reset
        limiter.reset()

        # Should be able to attempt again
        assert limiter.check_and_record() is True
        assert limiter.check_and_record() is True

    def test_get_remaining_attempts(self):
        """Test that remaining attempts are calculated correctly."""
        limiter = SSHCaptureRateLimiter(max_attempts=3, window=60)

        assert limiter.get_remaining_attempts() == 3

        limiter.check_and_record()
        assert limiter.get_remaining_attempts() == 2

        limiter.check_and_record()
        assert limiter.get_remaining_attempts() == 1

        limiter.check_and_record()
        assert limiter.get_remaining_attempts() == 0

    def test_sliding_window(self):
        """Test that sliding window correctly expires old attempts."""
        limiter = SSHCaptureRateLimiter(max_attempts=2, window=2)  # 2 second window

        # First attempt
        limiter.check_and_record()
        time.sleep(1)  # Wait 1 second

        # Second attempt
        limiter.check_and_record()

        # Third attempt should fail (both attempts still in window)
        with pytest.raises(SSHCaptureError):
            limiter.check_and_record()

        # Wait for first attempt to expire (1 more second = 2s total)
        time.sleep(1.1)

        # Should now be able to attempt (first attempt expired)
        assert limiter.check_and_record() is True

    def test_error_message_includes_wait_time(self):
        """Test that error message tells user how long to wait."""
        limiter = SSHCaptureRateLimiter(max_attempts=2, window=60)

        limiter.check_and_record()
        limiter.check_and_record()

        with pytest.raises(SSHCaptureError, match=r"wait \d+ seconds"):
            limiter.check_and_record()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
