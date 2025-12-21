"""Schema initialization tests for SQLite and PostgreSQL."""

import pytest
import os
import tempfile
from app.services.database import DatabaseService


@pytest.mark.asyncio
async def test_sqlite_schema_created_directly():
    """Verify SQLite creates schema via SCHEMA constant."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sqlite_url = f"sqlite:///{tmpdir}/test_schema.db"
        db = DatabaseService(database_url=sqlite_url)

        # init_db() should create schema directly
        await db.init_db()

        # Verify tables exist
        tables = await db.pool.fetch_all(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        table_names = [t["name"] for t in tables]

        assert "tasks" in table_names
        assert "progress_snapshots" in table_names


@pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith("postgresql"),
    reason="PostgreSQL not configured",
)
@pytest.mark.asyncio
async def test_postgresql_schema_via_alembic():
    """Verify PostgreSQL schema managed by Alembic (not init_db)."""
    postgres_url = os.getenv("DATABASE_URL", "postgresql://...")
    db = DatabaseService(database_url=postgres_url)

    # init_db() should NOT create schema (Alembic does it)
    # This test just verifies init_db() doesn't crash
    await db.init_db()

    # Verify we're using PostgreSQL
    assert db.pool.db_type == "postgresql"
