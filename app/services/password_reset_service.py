"""
Service for password reset functionality.

Handles:
- Token generation and hashing
- Database operations for reset tokens
- Token validation and consumption
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import uuid4

from app.models.user import User
from app.services.postgres_database import DatabasePool
from app.services.user_database import get_user_db_service

logger = logging.getLogger(__name__)


def _parse_timestamp(value) -> Optional[datetime]:
    """Parse timestamp from database."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    return None


class PasswordResetService:
    """Service for password reset tokens operations."""

    def __init__(self, database_url: Optional[str] = None):
        """
        Args:
            database_url: Database URL. If None, uses DATABASE_URL env var.
        """
        self.pool = DatabasePool(database_url)

    async def init_db(self):
        """Initialize database connection."""
        await self.pool.connect()
        logger.info("Password reset service database connection established")

    def generate_reset_token(self) -> Tuple[str, str]:
        """
        Generate a cryptographically secure reset token.

        Returns:
            Tuple of (plaintext_token, token_hash)
        """
        # Generate 32 bytes of randomness (256 bits entropy)
        plaintext = secrets.token_urlsafe(32)

        # Hash for storage (SHA-256)
        token_hash = hashlib.sha256(plaintext.encode()).hexdigest()

        return plaintext, token_hash

    async def create_reset_token(
        self, user_id: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None
    ) -> str:
        """
        Create a new reset token in the database for the given user.

        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client User Agent

        Returns:
            Plaintext token to be sent to user
        """
        plaintext, token_hash = self.generate_reset_token()

        # Expiration: 1 hour from now
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        token_id = str(uuid4())

        query, params = self.pool.translate_query(
            """
            INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_id, user_id, token_hash, expires_at, ip_address, user_agent),
        )

        await self.pool.execute(query, *params)

        logger.warning(f"PASSWORD_RESET_TOKEN_CREATED: user_id={user_id}, expires_at={expires_at}")

        return plaintext

    async def validate_token(self, token_hash: str) -> Optional[User]:
        """
        Validate a reset token hash and return the associated user if valid.

        Checks:
        - Token exists in DB
        - Token is not expired
        - Token has not been used
        - Associated user is active and approved

        Args:
            token_hash: Hashed token from user

        Returns:
            User object if valid, None otherwise
        """
        query, params = self.pool.translate_query(
            """
            SELECT user_id, expires_at, used_at FROM password_reset_tokens
            WHERE token_hash = ? AND used_at IS NULL
            """,
            (token_hash,),
        )

        row = await self.pool.fetch_one(query, *params)
        if not row:
            logger.warning(
                f"PASSWORD_RESET_VALIDATION_FAILED: token not found or already used, hash={token_hash[:8]}..."
            )
            return None

        expires_at = _parse_timestamp(row["expires_at"])
        if expires_at and expires_at < datetime.now(timezone.utc):
            logger.warning(f"PASSWORD_RESET_VALIDATION_FAILED: token expired, user_id={row['user_id']}")
            return None

        # Get user details
        user_db = get_user_db_service()
        user = await user_db.get_user_by_id(row["user_id"])

        if not user or not user.is_active or not user.is_approved:
            logger.warning(f"PASSWORD_RESET_VALIDATION_FAILED: user inactive or not found, user_id={row['user_id']}")
            return None

        return user

    async def consume_token(self, token_hash: str) -> bool:
        """
        Mark a token as used.

        Args:
            token_hash: Hashed token to consume

        Returns:
            True if successful
        """
        used_at = datetime.now(timezone.utc)

        query, params = self.pool.translate_query(
            "UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ?", (used_at, token_hash)
        )

        await self.pool.execute(query, *params)
        return True

    async def invalidate_user_tokens(self, user_id: str) -> int:
        """
        Mark all unused tokens for a user as used (invalidation).

        Args:
            user_id: User ID

        Returns:
            Number of tokens invalidated
        """
        used_at = datetime.now(timezone.utc)

        query, params = self.pool.translate_query(
            "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL", (used_at, user_id)
        )

        # We don't easily get rowcount from this pool, but we can assume success
        await self.pool.execute(query, *params)
        return 0  # Placeholder for count

    async def cleanup_expired_tokens(self) -> int:
        """
        Delete expired tokens from database.

        Returns:
            Number of tokens deleted
        """
        now = datetime.now(timezone.utc)

        query, params = self.pool.translate_query("DELETE FROM password_reset_tokens WHERE expires_at < ?", (now,))

        await self.pool.execute(query, *params)
        return 0  # Placeholder for count


# Singleton instance
_password_reset_service: Optional[PasswordResetService] = None


def get_password_reset_service() -> PasswordResetService:
    """Get singleton instance of PasswordResetService."""
    global _password_reset_service
    if _password_reset_service is None:
        _password_reset_service = PasswordResetService()
    return _password_reset_service
