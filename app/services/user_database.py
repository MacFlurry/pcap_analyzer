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

import aiosqlite
from passlib.context import CryptContext

from app.models.user import User, UserCreate, UserRole

logger = logging.getLogger(__name__)

# Password hashing context (bcrypt with cost factor 12)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

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

    def __init__(self, db_path: str = "/data/pcap_analyzer.db"):
        """
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._ensure_data_dir()

    def _ensure_data_dir(self):
        """Create data directory if needed."""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

    async def init_db(self):
        """
        Initialize users table.
        Idempotent: can be called multiple times.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(USER_SCHEMA)
            await db.commit()

        logger.info(f"User database initialized at {self.db_path}")

    async def migrate_tasks_table(self):
        """
        Migrate tasks table to add owner_id column.
        Safe to call multiple times (column already exists check).
        """
        async with aiosqlite.connect(self.db_path) as db:
            try:
                # Check if column already exists
                async with db.execute("PRAGMA table_info(tasks)") as cursor:
                    columns = await cursor.fetchall()
                    column_names = [col[1] for col in columns]

                if "owner_id" not in column_names:
                    # Add column
                    await db.execute("ALTER TABLE tasks ADD COLUMN owner_id TEXT REFERENCES users(id)")
                    await db.execute("CREATE INDEX IF NOT EXISTS idx_tasks_owner_id ON tasks(owner_id)")
                    await db.commit()
                    logger.info("Tasks table migrated: added owner_id column")
                else:
                    logger.debug("Tasks table already has owner_id column")

            except Exception as e:
                logger.error(f"Error migrating tasks table: {e}")
                # Non-critical, continue

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
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # Check if admin already exists
            async with db.execute(
                "SELECT COUNT(*) as count FROM users WHERE role = 'admin'"
            ) as cursor:
                row = await cursor.fetchone()
                admin_count = row["count"] if row else 0

            if admin_count > 0:
                logger.info("Admin account already exists")
                return None

            # Generate random password (20 chars, URL-safe)
            random_password = secrets.token_urlsafe(20)[:20]

            # Create admin user
            admin_user = UserCreate(
                username="admin",
                email="admin@pcap-analyzer.local",
                password=random_password,
            )

            await self.create_user(admin_user, role=UserRole.ADMIN)

            logger.warning("=" * 80)
            logger.warning("🔒 ADMIN BRISE-GLACE ACCOUNT CREATED")
            logger.warning("=" * 80)
            logger.warning(f"Username: admin")
            logger.warning(f"Password: {random_password}")
            logger.warning("")
            logger.warning("⚠️  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!")
            logger.warning("   Use: PUT /api/users/me with new password")
            logger.warning("=" * 80)

            return random_password

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

    async def create_user(self, user_data: UserCreate, role: UserRole = UserRole.USER, auto_approve: bool = False) -> User:
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

        async with aiosqlite.connect(self.db_path) as db:
            try:
                await db.execute(
                    """
                    INSERT INTO users (id, username, email, hashed_password, role, is_approved,
                                     approved_by, approved_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        created_at,
                    ),
                )
                await db.commit()

            except aiosqlite.IntegrityError as e:
                if "username" in str(e):
                    raise ValueError("Username already exists")
                elif "email" in str(e):
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
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username.lower(),),
            ) as cursor:
                row = await cursor.fetchone()

        if not row:
            return None

        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            hashed_password=row["hashed_password"],
            role=UserRole(row["role"]),
            is_active=bool(row["is_active"]),
            is_approved=bool(row.get("is_approved", False)),
            approved_by=row.get("approved_by"),
            approved_at=datetime.fromisoformat(row["approved_at"]) if row.get("approved_at") else None,
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
        )

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,),
            ) as cursor:
                row = await cursor.fetchone()

        if not row:
            return None

        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            hashed_password=row["hashed_password"],
            role=UserRole(row["role"]),
            is_active=bool(row["is_active"]),
            is_approved=bool(row.get("is_approved", False)),
            approved_by=row.get("approved_by"),
            approved_at=datetime.fromisoformat(row["approved_at"]) if row.get("approved_at") else None,
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
        )

    async def update_last_login(self, user_id: str):
        """Update last login timestamp."""
        timestamp = datetime.now(timezone.utc)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (timestamp, user_id),
            )
            await db.commit()

    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user by username and password.

        Args:
            username: Username
            password: Plain text password

        Returns:
            User if authentication succeeds, None otherwise
        """
        user = await self.get_user_by_username(username)

        if not user:
            # Run hash anyway to prevent timing attacks
            self.hash_password("dummy_password_to_prevent_timing_attack")
            return None

        if not user.is_active:
            return None

        if not self.verify_password(password, user.hashed_password):
            return None

        # Update last login
        await self.update_last_login(user.id)

        return user

    async def update_password(self, user_id: str, new_password: str):
        """
        Update user's password.

        Args:
            user_id: User ID
            new_password: New password (will be hashed)
        """
        hashed_password = self.hash_password(new_password)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE users SET hashed_password = ? WHERE id = ?",
                (hashed_password, user_id),
            )
            await db.commit()

        logger.info(f"Password updated for user_id: {user_id}")

    async def get_all_users(self, limit: int = 100) -> list[User]:
        """
        Get all users (admin only).

        Args:
            limit: Maximum number of users to return

        Returns:
            List of users
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()

        users = []
        for row in rows:
            users.append(
                User(
                    id=row["id"],
                    username=row["username"],
                    email=row["email"],
                    hashed_password=row["hashed_password"],
                    role=UserRole(row["role"]),
                    is_active=bool(row["is_active"]),
                    is_approved=bool(row.get("is_approved", False)),
                    approved_by=row.get("approved_by"),
                    approved_at=datetime.fromisoformat(row["approved_at"]) if row.get("approved_at") else None,
                    created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(timezone.utc),
                    last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
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

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                UPDATE users
                SET is_approved = 1, approved_by = ?, approved_at = ?
                WHERE id = ?
                """,
                (approver_id, approved_at, user_id),
            )
            await db.commit()
            updated = cursor.rowcount > 0

        if updated:
            logger.info(f"User {user_id} approved by {approver_id}")

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
        data_dir = os.getenv("DATA_DIR", "/data")
        db_path = f"{data_dir}/pcap_analyzer.db"
        _user_db_service = UserDatabaseService(db_path=db_path)
    return _user_db_service
