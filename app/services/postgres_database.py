"""
PostgreSQL database service with asyncpg connection pooling.

This service provides:
- Auto-detection of database type (SQLite vs PostgreSQL)
- Connection pooling for PostgreSQL (asyncpg)
- Backward compatibility with SQLite (aiosqlite)
- SQL query translation for PostgreSQL ($1, $2 syntax)

Usage:
    DATABASE_URL environment variable controls which DB to use:
    - sqlite:///path/to/db.db -> SQLite
    - postgresql://user:pass@host/db -> PostgreSQL
"""

import logging
import os
from typing import Any, Optional
from urllib.parse import urlparse

import aiosqlite
import asyncpg

logger = logging.getLogger(__name__)


class DatabasePool:
    """
    Database connection pool that supports both SQLite and PostgreSQL.

    Auto-detects database type from DATABASE_URL and manages connections accordingly.
    """

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize database pool.

        Args:
            database_url: Database URL (format: dialect://...)
                         If None, uses DATABASE_URL env var or defaults to SQLite
        """
        self.database_url = database_url or os.getenv(
            "DATABASE_URL", "sqlite:///data/pcap_analyzer.db"
        )

        # Parse URL to detect database type
        parsed = urlparse(self.database_url)
        self.db_type = parsed.scheme.split("+")[0]  # Handle postgresql+asyncpg

        # Connection pool (asyncpg for PostgreSQL)
        self.pool: Optional[asyncpg.Pool] = None

        # SQLite path (if using SQLite)
        self.sqlite_path: Optional[str] = None
        if self.db_type == "sqlite":
            # Extract path from sqlite:///path/to/db.db
            self.sqlite_path = self.database_url.replace("sqlite:///", "")
            if not self.sqlite_path.startswith("/"):
                # Relative path, make absolute
                self.sqlite_path = os.path.abspath(self.sqlite_path)

        logger.info(f"Database pool initialized: {self.db_type}")

    async def connect(self):
        """
        Create connection pool (PostgreSQL only).

        For SQLite, connections are created per-query.

        Security:
            Supports TLS/SSL for PostgreSQL connections via DATABASE_SSL_MODE env var.
            Modes: disable, prefer (default), require, verify-full
        """
        if self.db_type == "postgresql":
            if not self.pool:
                # TLS/SSL configuration (OWASP ASVS V2.8, CWE-319 mitigation)
                ssl_mode = os.getenv("DATABASE_SSL_MODE", "prefer")  # prefer, require, verify-full, disable

                # Map SSL mode to asyncpg parameter
                ssl_param = None
                if ssl_mode == "disable":
                    ssl_param = False
                elif ssl_mode == "prefer":
                    ssl_param = "prefer"  # Try SSL, fallback to non-SSL (default for backward compatibility)
                elif ssl_mode == "require":
                    ssl_param = "require"  # Require SSL but don't verify certificate
                elif ssl_mode == "verify-full":
                    ssl_param = "verify-full"  # Require SSL and verify certificate (recommended for production)
                else:
                    logger.warning(f"Invalid DATABASE_SSL_MODE '{ssl_mode}', defaulting to 'prefer'")
                    ssl_param = "prefer"

                # Create asyncpg connection pool
                self.pool = await asyncpg.create_pool(
                    self.database_url,
                    min_size=2,
                    max_size=10,
                    command_timeout=60,
                    ssl=ssl_param,  # ✅ TLS/SSL enforcement
                )
                logger.info(f"PostgreSQL connection pool created (SSL mode: {ssl_mode})")
        elif self.db_type == "sqlite":
            # SQLite: ensure data directory exists
            if self.sqlite_path:
                db_dir = os.path.dirname(self.sqlite_path)
                os.makedirs(db_dir, exist_ok=True)
            logger.info(f"SQLite database path: {self.sqlite_path}")
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")

    async def close(self):
        """Close connection pool (PostgreSQL only)."""
        if self.pool:
            await self.pool.close()
            self.pool = None
            logger.info("PostgreSQL connection pool closed")

    async def execute(self, query: str, *args, return_result: bool = False) -> Optional[Any]:
        """
        Execute a query (INSERT, UPDATE, DELETE).

        Args:
            query: SQL query
            *args: Query parameters
            return_result: If True, return result (for RETURNING clauses)

        Returns:
            Result if return_result=True, None otherwise
        """
        if self.db_type == "postgresql":
            async with self.pool.acquire() as conn:
                if return_result:
                    return await conn.fetchrow(query, *args)
                else:
                    await conn.execute(query, *args)
                    return None
        else:  # SQLite
            async with aiosqlite.connect(self.sqlite_path) as db:
                cursor = await db.execute(query, args)
                if return_result:
                    result = await cursor.fetchone()
                    await db.commit()
                    return result
                else:
                    await db.commit()
                    return None

    async def fetch_one(self, query: str, *args) -> Optional[dict]:
        """
        Fetch one row.

        Args:
            query: SQL query
            *args: Query parameters

        Returns:
            Row as dict, or None if not found
        """
        if self.db_type == "postgresql":
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(query, *args)
                return dict(row) if row else None
        else:  # SQLite
            async with aiosqlite.connect(self.sqlite_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, args) as cursor:
                    row = await cursor.fetchone()
                    return dict(row) if row else None

    async def fetch_all(self, query: str, *args) -> list[dict]:
        """
        Fetch all rows.

        Args:
            query: SQL query
            *args: Query parameters

        Returns:
            List of rows as dicts
        """
        if self.db_type == "postgresql":
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, *args)
                return [dict(row) for row in rows]
        else:  # SQLite
            async with aiosqlite.connect(self.sqlite_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, args) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(row) for row in rows]

    async def execute_script(self, script: str):
        """
        Execute a SQL script (multiple statements).

        Args:
            script: SQL script
        """
        if self.db_type == "postgresql":
            async with self.pool.acquire() as conn:
                await conn.execute(script)
        else:  # SQLite
            async with aiosqlite.connect(self.sqlite_path) as db:
                await db.executescript(script)
                await db.commit()

    def translate_query(self, query: str, params: tuple) -> tuple[str, tuple]:
        """
        Translate query from SQLite style (?) to PostgreSQL style ($1, $2, ...).

        Args:
            query: SQL query with ? placeholders
            params: Query parameters

        Returns:
            Tuple of (translated_query, params)
        """
        if self.db_type == "postgresql":
            # Replace ? with $1, $2, $3, ...
            param_count = 1
            translated_query = ""
            for char in query:
                if char == "?":
                    translated_query += f"${param_count}"
                    param_count += 1
                else:
                    translated_query += char
            return translated_query, params
        else:
            # SQLite: no translation needed
            return query, params


# Singleton instance
_db_pool: Optional[DatabasePool] = None


async def get_db_pool() -> DatabasePool:
    """
    Get singleton database pool instance.

    Returns:
        DatabasePool instance
    """
    global _db_pool
    if _db_pool is None:
        _db_pool = DatabasePool()
        await _db_pool.connect()
    return _db_pool


async def close_db_pool():
    """Close database pool (cleanup on shutdown)."""
    global _db_pool
    if _db_pool:
        await _db_pool.close()
        _db_pool = None
