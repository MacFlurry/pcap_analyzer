"""
User database service for authentication.

Handles:
- User CRUD operations
- Password hashing (bcrypt)
- Admin brise-glace creation
- Multi-tenant isolation

References:
- OWASP Password Storage Cheat Sheet
- Bcrypt cost factor 12 (recommended for 2025)
"""

import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from passlib.context import CryptContext

from app.models.user import User, UserCreate, UserRole
from app.services.postgres_database import DatabasePool

logger = logging.getLogger(__name__)

# Password hashing context (bcrypt with cost factor 12)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def _parse_timestamp(value) -> Optional[datetime]:
    """
    Parse timestamp from database (handles both SQLite strings and PostgreSQL datetime objects).

    Args:
        value: String (SQLite) or datetime (PostgreSQL) or None

    Returns:
        datetime object or None
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        # PostgreSQL returns datetime objects directly
        return value
    if isinstance(value, str):
        # SQLite returns ISO format strings
        return datetime.fromisoformat(value)
    return None

# Database schema for users table
# NOTE: For PostgreSQL, use Alembic migrations instead of this schema
USER_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT 1,
    is_approved BOOLEAN NOT NULL DEFAULT 0,
    approved_by TEXT,
    approved_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    last_login TIMESTAMP,
    CONSTRAINT role_check CHECK (role IN ('admin', 'user'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
"""

# Modify tasks table to add owner_id (multi-tenant)
TASKS_MIGRATION = """
-- Add owner_id column to tasks table (if not exists)
ALTER TABLE tasks ADD COLUMN owner_id TEXT REFERENCES users(id);

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_tasks_owner_id ON tasks(owner_id);
"""


class UserDatabaseService:
    """Service for user database operations."""

    def __init__(self, database_url: Optional[str] = None):
        """
        Args:
            database_url: Database URL (sqlite:/// or postgresql://). If None, uses DATABASE_URL env var.
        """
        self.pool = DatabasePool(database_url)

    async def init_db(self):
        """
        Initialize users table.
        Idempotent: can be called multiple times.

        Note: For PostgreSQL, schema should be managed by Alembic migrations.
              For SQLite, we create schema directly.
        """
        await self.pool.connect()

        if self.pool.db_type == "sqlite":
            # SQLite: create schema directly
            await self.pool.execute_script(USER_SCHEMA)
            logger.info("SQLite user database initialized")
        else:
            # PostgreSQL: schema managed by Alembic migrations
            logger.info("PostgreSQL user database connected (schema managed by Alembic)")

    async def migrate_tasks_table(self):
        """
        Migrate tasks table to add owner_id column.
        Safe to call multiple times (column already exists check).
        Note: For PostgreSQL, this should be handled by Alembic migrations.
        """
        if self.pool.db_type == "sqlite":
            try:
                # SQLite: Check if column already exists
                result = await self.pool.fetch_all("PRAGMA table_info(tasks)")
                column_names = [col["name"] if "name" in col else col[1] for col in result]

                if "owner_id" not in column_names:
                    # Add column
                    await self.pool.execute("ALTER TABLE tasks ADD COLUMN owner_id TEXT REFERENCES users(id)")
                    await self.pool.execute("CREATE INDEX IF NOT EXISTS idx_tasks_owner_id ON tasks(owner_id)")
                    logger.info("Tasks table migrated: added owner_id column")
                else:
                    logger.debug("Tasks table already has owner_id column")

            except Exception as e:
                logger.error(f"Error migrating tasks table: {e}")
                # Non-critical, continue
        else:
            # PostgreSQL: migrations handled by Alembic
            logger.debug("PostgreSQL detected: skipping manual migration (use Alembic)")

    async def create_admin_breakglass_if_not_exists(self) -> Optional[str]:
        """
        Create admin brise-glace account if no admin exists.

        Returns:
            Generated password (to display in logs), or None if admin already exists

        Behavior (like Grafana):
        1. Check if any admin user exists
        2. If not, create admin with random password
        3. Return password to display in startup logs
        4. Admin can change password via /users/me endpoint
        """
        # Check if admin already exists
        query, params = self.pool.translate_query(
            "SELECT COUNT(*) as count FROM users WHERE role = ?",
            ("admin",),
        )
        row = await self.pool.fetch_one(query, *params)
        admin_count = row["count"] if row else 0

        if admin_count > 0:
            logger.info("Admin account already exists")
            return None

        # Read password from Docker secrets or generate random
        admin_password = self._get_admin_password()

        # Create admin user
        admin_user = UserCreate(
            username="admin",
            email="omegabk@gmail.com",
            password=admin_password,
        )

        await self.create_user(admin_user, role=UserRole.ADMIN)

        logger.warning("=" * 80)
        logger.warning("🔒 ADMIN BRISE-GLACE ACCOUNT CREATED")
        logger.warning("=" * 80)
        logger.warning(f"Username: admin")
        logger.warning(f"Password: {admin_password}")
        logger.warning("")
        logger.warning("⚠️  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!")
        logger.warning("   Use: PUT /api/users/me with new password")
        logger.warning("=" * 80)

        return admin_password

    def _get_admin_password(self) -> str:
        """
        Get admin password from Docker secrets or generate random fallback.

        Priority:
        1. /var/run/secrets/admin_password (Docker/Kubernetes)
        2. Generate random password (dev/fallback)

        Returns:
            Admin password string
        """
        from pathlib import Path

        # Try to read from Docker/Kubernetes secrets
        secrets_file = Path("/var/run/secrets/admin_password")
        if secrets_file.exists():
            try:
                password = secrets_file.read_text().strip()
                if password:
                    logger.info("✅ Admin password loaded from /var/run/secrets/admin_password")
                    return password
                else:
                    logger.warning("⚠️  Admin password file is empty, generating random password")
            except Exception as e:
                logger.warning(f"⚠️  Failed to read {secrets_file}: {e}, generating random password")

        # Fallback: generate random password (dev mode or secrets not available)
        logger.info("🔐 Generating random admin password (no secrets file found)")
        return secrets.token_urlsafe(24)[:24]

    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt (cost factor 12).

        Args:
            password: Plain text password

        Returns:
            Hashed password (bcrypt format)
        """
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.

        Args:
            plain_password: Plain text password from user
            hashed_password: Hashed password from database

        Returns:
            True if password matches
        """
        return pwd_context.verify(plain_password, hashed_password)

    async def create_user(
        self, user_data: UserCreate, role: UserRole = UserRole.USER, auto_approve: bool = False, password_must_change: bool = False
    ) -> User:
        """
        Create a new user.

        Args:
            user_data: User registration data
            role: User role (default: user)
            auto_approve: If True, approve user immediately (for admin accounts)

        Returns:
            Created user

        Raises:
            ValueError: If username or email already exists
        """
        from uuid import uuid4

        user_id = str(uuid4())
        hashed_password = self.hash_password(user_data.password)
        created_at = datetime.now(timezone.utc)

        # Auto-approve admins and if explicitly requested
        is_approved = auto_approve or role == UserRole.ADMIN
        approved_at = created_at if is_approved else None
        approved_by = user_id if is_approved else None  # Self-approved for initial admin

        try:
            query, params = self.pool.translate_query(
                """
                INSERT INTO users (id, username, email, hashed_password, role, is_approved,
                                 approved_by, approved_at, password_must_change, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    user_data.username.lower(),
                    user_data.email.lower(),
                    hashed_password,
                    role.value,
                    is_approved,
                    approved_by,
                    approved_at,
                    password_must_change,
                    created_at,
                ),
            )
            await self.pool.execute(query, *params)

        except Exception as e:
            error_str = str(e).lower()
            if "username" in error_str or "unique" in error_str:
                raise ValueError("Username already exists")
            elif "email" in error_str:
                raise ValueError("Email already exists")
            else:
                raise ValueError(f"Database error: {e}")

        logger.info(f"User created: {user_data.username} (role: {role.value}, approved: {is_approved})")

        return User(
            id=user_id,
            username=user_data.username.lower(),
            email=user_data.email.lower(),
            hashed_password=hashed_password,
            role=role,
            is_approved=is_approved,
            approved_by=approved_by,
            approved_at=approved_at,
            password_must_change=password_must_change,
            created_at=created_at,
        )

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.

        Args:
            username: Username (case-insensitive)

        Returns:
            User if found, None otherwise
        """
        query, params = self.pool.translate_query(
            "SELECT * FROM users WHERE username = ?",
            (username.lower(),),
        )
        row = await self.pool.fetch_one(query, *params)

        if not row:
            return None

        return User(
            id=str(row["id"]),
            username=row["username"],
            email=row["email"],
            hashed_password=row["hashed_password"],
            role=UserRole(row["role"]),
            is_active=bool(row["is_active"]),
            is_approved=bool(row.get("is_approved", False)),
            approved_by=str(row["approved_by"]) if row.get("approved_by") else None,
            approved_at=_parse_timestamp(row.get("approved_at")),
            password_must_change=bool(row.get("password_must_change", False)),
            created_at=_parse_timestamp(row.get("created_at")) or datetime.now(timezone.utc),
            last_login=_parse_timestamp(row.get("last_login")),
        )

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        query, params = self.pool.translate_query(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        )
        row = await self.pool.fetch_one(query, *params)

        if not row:
            return None

        return User(
            id=str(row["id"]),
            username=row["username"],
            email=row["email"],
            hashed_password=row["hashed_password"],
            role=UserRole(row["role"]),
            is_active=bool(row["is_active"]),
            is_approved=bool(row.get("is_approved", False)),
            approved_by=str(row["approved_by"]) if row.get("approved_by") else None,
            approved_at=_parse_timestamp(row.get("approved_at")),
            password_must_change=bool(row.get("password_must_change", False)),
            created_at=_parse_timestamp(row.get("created_at")) or datetime.now(timezone.utc),
            last_login=_parse_timestamp(row.get("last_login")),
        )

    async def update_last_login(self, user_id: str):
        """Update last login timestamp."""
        timestamp = datetime.now(timezone.utc)

        query, params = self.pool.translate_query(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (timestamp, user_id),
        )
        await self.pool.execute(query, *params)

    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user by username and password.

        Args:
            username: Username
            password: Plain text password

        Returns:
            User if authentication succeeds, None otherwise

        Note:
            Returns None (no specific error) if account is not approved.
            Caller should check user.is_approved to provide specific error message.
        """
        user = await self.get_user_by_username(username)

        if not user:
            # Run hash anyway to prevent timing attacks
            self.hash_password("dummy_password_to_prevent_timing_attack")
            return None

        if not user.is_active:
            return None

        if not user.is_approved:
            # Account exists but not yet approved by admin
            return None

        if not self.verify_password(password, user.hashed_password):
            return None

        # Update last login
        await self.update_last_login(user.id)

        return user

    async def update_password(self, user_id: str, new_password: str):
        """
        Update user's password.
        Also resets password_must_change flag to False.

        Args:
            user_id: User ID
            new_password: New password (will be hashed)
        """
        hashed_password = self.hash_password(new_password)

        query, params = self.pool.translate_query(
            "UPDATE users SET hashed_password = ?, password_must_change = ? WHERE id = ?",
            (hashed_password, False, user_id),
        )
        await self.pool.execute(query, *params)

        logger.info(f"Password updated for user_id: {user_id} (password_must_change reset to False)")

    async def get_all_users(self, limit: int = 100) -> list[User]:
        """
        Get all users (admin only).

        Args:
            limit: Maximum number of users to return

        Returns:
            List of users
        """
        query, params = self.pool.translate_query(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = await self.pool.fetch_all(query, *params)

        users = []
        for row in rows:
            users.append(
                User(
                    id=str(row["id"]),
                    username=row["username"],
                    email=row["email"],
                    hashed_password=row["hashed_password"],
                    role=UserRole(row["role"]),
                    is_active=bool(row["is_active"]),
                    is_approved=bool(row.get("is_approved", False)),
                    approved_by=str(row["approved_by"]) if row.get("approved_by") else None,
                    approved_at=_parse_timestamp(row.get("approved_at")),
                    created_at=_parse_timestamp(row.get("created_at")) or datetime.now(timezone.utc),
                    last_login=_parse_timestamp(row.get("last_login")),
                )
            )

        return users

    async def approve_user(self, user_id: str, approver_id: str) -> bool:
        """
        Approve a user account.

        Args:
            user_id: User ID to approve
            approver_id: Admin user ID performing the approval

        Returns:
            True if approved successfully, False if user not found
        """
        approved_at = datetime.now(timezone.utc)

        query, params = self.pool.translate_query(
            """
            UPDATE users
            SET is_approved = TRUE, approved_by = ?, approved_at = ?
            WHERE id = ?
            """,
            (approver_id, approved_at, user_id),
        )
        await self.pool.execute(query, *params)

        # Verify update (fetch the user to check)
        user = await self.get_user_by_id(user_id)
        updated = user is not None and user.is_approved

        if updated:
            logger.info(f"User {user_id} approved by {approver_id}")

        return updated

    async def block_user(self, user_id: str) -> bool:
        """
        Block a user account (set is_active=False).

        Args:
            user_id: User ID to block

        Returns:
            True if blocked successfully, False if user not found
        """
        query, params = self.pool.translate_query(
            "UPDATE users SET is_active = FALSE WHERE id = ?",
            (user_id,),
        )
        await self.pool.execute(query, *params)

        # Verify update (fetch the user to check)
        user = await self.get_user_by_id(user_id)
        updated = user is not None and not user.is_active

        if updated:
            logger.info(f"User {user_id} blocked (is_active=False)")

        return updated

    async def unblock_user(self, user_id: str) -> bool:
        """
        Unblock a user account (set is_active=True).

        Args:
            user_id: User ID to unblock

        Returns:
            True if unblocked successfully, False if user not found
        """
        query, params = self.pool.translate_query(
            "UPDATE users SET is_active = TRUE WHERE id = ?",
            (user_id,),
        )
        await self.pool.execute(query, *params)

        # Verify update (fetch the user to check)
        user = await self.get_user_by_id(user_id)
        updated = user is not None and user.is_active

        if updated:
            logger.info(f"User {user_id} unblocked (is_active=True)")

        return updated


# Singleton instance
_user_db_service: Optional[UserDatabaseService] = None


def get_user_db_service() -> UserDatabaseService:
    """
    Get singleton instance of UserDatabaseService.

    Returns:
        UserDatabaseService instance
    """
    global _user_db_service
    if _user_db_service is None:
        # Auto-detect database from DATABASE_URL environment variable
        # Defaults to SQLite if not set
        _user_db_service = UserDatabaseService()
    return _user_db_service
