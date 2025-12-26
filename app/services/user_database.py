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
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import bcrypt

from app.models.user import User, UserCreate, UserRole
from app.services.postgres_database import DatabasePool

logger = logging.getLogger(__name__)

# Bcrypt cost factor (12 rounds = recommended for 2025)
BCRYPT_ROUNDS = 12


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


def _parse_backup_codes(value) -> Optional[list[str]]:
    """Parse backup codes from JSON string."""
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return []


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
    password_must_change BOOLEAN NOT NULL DEFAULT 0,
    is_2fa_enabled BOOLEAN NOT NULL DEFAULT 0,
    totp_secret TEXT,
    backup_codes TEXT,
    created_at TIMESTAMP NOT NULL,
    last_login TIMESTAMP,
    CONSTRAINT role_check CHECK (role IN ('admin', 'user'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
"""

# Password history table schema (Issue #23: Enhanced Password Policy)
PASSWORD_HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS password_history (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    hashed_password TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_user_created ON password_history(user_id, created_at DESC);
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
            await self.pool.execute_script(PASSWORD_HISTORY_SCHEMA)
            logger.info("SQLite user database initialized (with password_history table)")
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
        Create or update admin brise-glace account.

        Returns:
            Admin password (to display in logs), or None if admin exists and no secrets file

        Behavior:
        1. If no admin exists → create admin with password from secrets or random
        2. If admin exists AND secrets file exists → update password from secrets file
        3. If admin exists AND no secrets file → do nothing (keep existing password)
        4. Return password to display in startup logs

        This ensures that rebuilding the container with a new secrets file will
        automatically update the admin password.
        """
        from pathlib import Path

        # Check if secrets file exists
        secrets_file = Path("/var/run/secrets/admin_password")
        secrets_password = None
        if secrets_file.exists():
            try:
                secrets_password = secrets_file.read_text().strip()
                if not secrets_password:
                    logger.warning("⚠️  Admin password file is empty")
                    secrets_password = None
            except Exception as e:
                logger.warning(f"⚠️  Failed to read {secrets_file}: {e}")
                secrets_password = None

        # Check if admin user already exists
        query, params = self.pool.translate_query(
            "SELECT id, username FROM users WHERE username = ?",
            ("admin",),
        )
        admin_user = await self.pool.fetch_one(query, *params)

        if admin_user:
            # Admin exists
            if secrets_password:
                # Update admin password with secrets file
                admin_id = str(admin_user["id"])
                hashed_password = self.hash_password(secrets_password)

                query, params = self.pool.translate_query(
                    "UPDATE users SET hashed_password = ? WHERE id = ?",
                    (hashed_password, admin_id),
                )
                await self.pool.execute(query, *params)

                # Security: Display password to STDOUT only (not in persistent logs)
                # CWE-532 mitigation: Passwords must not be stored in log files
                print("=" * 80, flush=True)
                print("🔐 ADMIN PASSWORD UPDATED FROM SECRETS FILE", flush=True)
                print("=" * 80, flush=True)
                print(f"Username: admin", flush=True)
                print(f"Password: {secrets_password}", flush=True)
                print("", flush=True)
                print("📝 Password synchronized with /var/run/secrets/admin_password", flush=True)
                print("=" * 80, flush=True)

                # Log security event WITHOUT password (CWE-532 compliance)
                logger.warning("🔐 Admin password updated from secrets file (password displayed on STDOUT only)")

                return secrets_password
            else:
                # Admin exists but no secrets file → keep existing password
                logger.info("Admin account already exists (password unchanged)")
                return None
        else:
            # No admin exists → create new admin
            admin_password = secrets_password if secrets_password else self._generate_random_password()

            admin_user_create = UserCreate(
                username="admin",
                email="omegabk@gmail.com",
                password=admin_password,
            )

            await self.create_user(admin_user_create, role=UserRole.ADMIN, auto_approve=True)

            # Security: Display password to STDOUT only (not in persistent logs)
            # CWE-532 mitigation: Passwords must not be stored in log files
            print("=" * 80, flush=True)
            print("🔒 ADMIN BRISE-GLACE ACCOUNT CREATED", flush=True)
            print("=" * 80, flush=True)
            print(f"Username: admin", flush=True)
            print(f"Password: {admin_password}", flush=True)
            print("", flush=True)
            if secrets_password:
                print("📝 Password loaded from /var/run/secrets/admin_password", flush=True)
            else:
                print("🔐 Random password generated (no secrets file found)", flush=True)
            print("", flush=True)
            print("⚠️  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!", flush=True)
            print("   Use: PUT /api/users/me with new password", flush=True)
            print("=" * 80, flush=True)

            # Log security event WITHOUT password (CWE-532 compliance)
            logger.warning("🔒 Admin brise-glace account created (password displayed on STDOUT only)")

            return admin_password

    def _generate_random_password(self) -> str:
        """Generate secure random password (24 chars)."""
        return secrets.token_urlsafe(24)[:24]

    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt (cost factor 12).

        Args:
            password: Plain text password

        Returns:
            Hashed password (bcrypt format)
        """
        # Truncate password to 72 bytes (bcrypt limitation)
        password_bytes = password.encode('utf-8')[:72]
        salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.

        Args:
            plain_password: Plain text password from user
            hashed_password: Hashed password from database

        Returns:
            True if password matches
        """
        # Truncate password to 72 bytes (bcrypt limitation)
        password_bytes = plain_password.encode('utf-8')[:72]
        hashed_bytes = hashed_password.encode('utf-8')
        try:
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        except Exception as e:
            logger.error(f"Error during password verification: {e}")
            return False





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

            # Add initial password to history (Issue #23)
            await self.add_password_to_history(user_id, hashed_password)

        except Exception as e:
            error_str = str(e).lower()
            if "idx_users_email" in error_str or "users_email_key" in error_str:
                raise ValueError("Email already exists")
            elif "idx_users_username" in error_str or "users_username_key" in error_str:
                raise ValueError("Username already exists")
            elif "username" in error_str:
                raise ValueError("Username already exists")
            elif "email" in error_str:
                raise ValueError("Email already exists")
            elif "unique" in error_str:
                # Fallback for other unique constraints or SQLite
                raise ValueError("Username already exists")
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
            is_2fa_enabled=bool(row.get("is_2fa_enabled", False)),
            totp_secret=row.get("totp_secret"),
            backup_codes=_parse_backup_codes(row.get("backup_codes")),
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
            is_2fa_enabled=bool(row.get("is_2fa_enabled", False)),
            totp_secret=row.get("totp_secret"),
            backup_codes=_parse_backup_codes(row.get("backup_codes")),
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
        Update user's password (Issue #23: with password history check).
        Also resets password_must_change flag to False.

        Args:
            user_id: User ID
            new_password: New password (will be hashed)

        Raises:
            ValueError: If password was used recently (reuse of last 5)
        """
        # Check password reuse (Issue #23)
        is_reused = await self.check_password_reuse(user_id, new_password)
        if is_reused:
            raise ValueError("Password was used recently. Please choose a different password (last 5 passwords cannot be reused)")

        hashed_password = self.hash_password(new_password)

        query, params = self.pool.translate_query(
            "UPDATE users SET hashed_password = ?, password_must_change = ? WHERE id = ?",
            (hashed_password, False, user_id),
        )
        await self.pool.execute(query, *params)

        # Add new password to history (Issue #23)
        await self.add_password_to_history(user_id, hashed_password)

        logger.info(f"Password updated for user_id: {user_id} (password_must_change reset to False)")

    async def add_password_to_history(self, user_id: str, hashed_password: str):
        """
        Add a password to user's password history (Issue #23).

        Automatically cleans up old history entries (keeps only last 5).

        Args:
            user_id: User ID
            hashed_password: Hashed password to add to history
        """
        from uuid import uuid4

        # 1. Add new password to history
        history_id = str(uuid4())
        created_at = datetime.now(timezone.utc)

        query, params = self.pool.translate_query(
            "INSERT INTO password_history (id, user_id, hashed_password, created_at) VALUES (?, ?, ?, ?)",
            (history_id, user_id, hashed_password, created_at),
        )
        await self.pool.execute(query, *params)

        # 2. Clean up old history (keep only last 5)
        # Get all history entries for this user ordered by created_at DESC
        query, params = self.pool.translate_query(
            "SELECT id FROM password_history WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,),
        )
        rows = await self.pool.fetch_all(query, *params)

        # If more than 5 entries, delete the oldest ones
        if len(rows) > 5:
            old_ids = [row[0] for row in rows[5:]]  # Everything beyond the first 5

            # Build DELETE query with IN clause
            placeholders = ', '.join(['?' for _ in old_ids])
            delete_query = f"DELETE FROM password_history WHERE id IN ({placeholders})"
            delete_query, delete_params = self.pool.translate_query(delete_query, tuple(old_ids))
            await self.pool.execute(delete_query, *delete_params)

            logger.debug(f"Cleaned up {len(old_ids)} old password history entries for user {user_id}")

    async def check_password_reuse(self, user_id: str, new_password: str) -> bool:
        """
        Check if new password was used recently (Issue #23: prevent reuse of last 5).

        Args:
            user_id: User ID
            new_password: New password (plaintext) to check

        Returns:
            True if password was used before (reuse detected), False otherwise
        """
        # Get last 5 password hashes
        query, params = self.pool.translate_query(
            "SELECT hashed_password FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
            (user_id,),
        )
        rows = await self.pool.fetch_all(query, *params)

        # Check if new password matches any of the last 5
        for row in rows:
            old_hashed_password = row["hashed_password"]
            if self.verify_password(new_password, old_hashed_password):
                return True  # Reuse detected!

        return False  # Password not reused

    async def get_all_users(
        self, 
        limit: int = 100, 
        offset: int = 0, 
        status_filter: Optional[str] = None, 
        role_filter: Optional[str] = None
    ) -> tuple[list[User], int]:
        """
        Get all users with pagination and filtering (admin only).

        Args:
            limit: Maximum number of users to return
            offset: Number of users to skip
            status_filter: Filter by approval status ("pending", "approved", "blocked")
            role_filter: Filter by user role ("admin", "user")

        Returns:
            Tuple of (list of users, total count matching filters)
        """
        effective_offset = offset
        base_query = "FROM users"
        conditions = []
        params = []

        if status_filter:
            if status_filter == "pending":
                conditions.append("is_approved = ?")
                params.append(False)
            elif status_filter == "approved":
                conditions.append("is_approved = ?")
                params.append(True)
                conditions.append("is_active = ?")
                params.append(True)
            elif status_filter == "blocked":
                conditions.append("is_active = ?")
                params.append(False)

        if role_filter:
            conditions.append("role = ?")
            params.append(role_filter)

        where_clause = ""
        if conditions:
            where_clause = " WHERE " + " AND ".join(conditions)

        # 1. Get total count
        count_query = f"SELECT COUNT(*) as total {base_query}{where_clause}"
        count_query, count_params = self.pool.translate_query(count_query, tuple(params))
        count_row = await self.pool.fetch_one(count_query, *count_params)
        total = int(count_row["total"]) if count_row else 0

        # 2. Get paginated results
        query = f"SELECT * {base_query}{where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        all_params = params + [limit, effective_offset]
        query, all_params = self.pool.translate_query(query, tuple(all_params))
        rows = await self.pool.fetch_all(query, *all_params)

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
                    is_2fa_enabled=bool(row.get("is_2fa_enabled", False)),
                    created_at=_parse_timestamp(row.get("created_at")) or datetime.now(timezone.utc),
                    last_login=_parse_timestamp(row.get("last_login")),
                )
            )

        return users, total

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

    async def enable_2fa(self, user_id: str, totp_secret: str, backup_codes: list[str]):
        """
        Enable 2FA for a user.
        
        Args:
            user_id: User ID
            totp_secret: The TOTP secret key
            backup_codes: List of backup codes
        """
        backup_codes_json = json.dumps(backup_codes)
        query, params = self.pool.translate_query(
            "UPDATE users SET is_2fa_enabled = ?, totp_secret = ?, backup_codes = ? WHERE id = ?",
            (True, totp_secret, backup_codes_json, user_id),
        )
        await self.pool.execute(query, *params)
        logger.info(f"2FA enabled for user {user_id}")

    async def disable_2fa(self, user_id: str):
        """Disable 2FA for a user."""
        query, params = self.pool.translate_query(
            "UPDATE users SET is_2fa_enabled = ?, totp_secret = NULL, backup_codes = NULL WHERE id = ?",
            (False, user_id),
        )
        await self.pool.execute(query, *params)
        logger.info(f"2FA disabled for user {user_id}")

    async def consume_backup_code(self, user_id: str, code: str) -> bool:
        """
        Verify and consume a backup code.
        Returns True if code was valid and consumed.
        """
        user = await self.get_user_by_id(user_id)
        if not user or not user.backup_codes:
            return False
            
        if code in user.backup_codes:
            # Remove used code
            new_codes = [c for c in user.backup_codes if c != code]
            new_codes_json = json.dumps(new_codes)
            
            query, params = self.pool.translate_query(
                "UPDATE users SET backup_codes = ? WHERE id = ?",
                (new_codes_json, user_id),
            )
            await self.pool.execute(query, *params)
            logger.info(f"Backup code consumed for user {user_id}")
            return True
            
        return False


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
