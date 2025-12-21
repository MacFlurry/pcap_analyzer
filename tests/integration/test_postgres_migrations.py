"""
Alembic migration tests for PostgreSQL (deployment safety).

Tests:
- Migration upgrade from scratch
- Migration downgrade to base
- Migration idempotency
"""

import pytest
from alembic import command
from alembic.config import Config


@pytest.mark.asyncio
async def test_migration_upgrade_from_scratch(test_postgres_db):
    """Verify migrations create all tables."""
    # Drop all tables
    await test_postgres_db.pool.execute("DROP SCHEMA public CASCADE")
    await test_postgres_db.pool.execute("CREATE SCHEMA public")

    # Run migrations
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")

    # Verify tables exist
    tables = await test_postgres_db.pool.fetch_all("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public'
    """)

    table_names = {row["table_name"] for row in tables}
    assert {"users", "tasks", "progress_snapshots"} <= table_names


@pytest.mark.asyncio
async def test_migration_downgrade_to_base(test_postgres_db):
    """Verify migration downgrade removes tables."""
    # Ensure tables exist
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")

    # Downgrade
    command.downgrade(alembic_cfg, "base")

    # Verify tables removed (or schema recreated)
    tables = await test_postgres_db.pool.fetch_all("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public'
    """)

    table_names = {row["table_name"] for row in tables}
    assert "tasks" not in table_names


@pytest.mark.asyncio
async def test_migration_idempotent(test_postgres_db):
    """Verify running migration twice is safe."""
    alembic_cfg = Config("alembic.ini")

    # Run migration twice
    command.upgrade(alembic_cfg, "head")
    command.upgrade(alembic_cfg, "head")  # Should be no-op

    # Verify tables still exist
    tables = await test_postgres_db.pool.fetch_all("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public'
    """)

    table_names = {row["table_name"] for row in tables}
    assert {"users", "tasks", "progress_snapshots"} <= table_names
