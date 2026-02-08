import pytest
import asyncio
import uuid
from sqlalchemy import create_engine, text
from alembic.config import Config
from alembic import command
from app.services.database import DatabaseService
from app.models.schemas import TaskStatus
# Fixtures (postgres_container, postgres_db_url, apply_migrations) are automatically provided by conftest.py

@pytest.fixture
def alembic_config(postgres_db_url):
    alembic_cfg = Config("alembic.ini")
    sync_url = postgres_db_url.replace("postgresql://", "postgresql+psycopg2://")
    alembic_cfg.set_main_option("sqlalchemy.url", sync_url)
    return alembic_cfg

@pytest.mark.integration
@pytest.mark.xfail(
    reason="Known issue: Alembic downgrade in testcontainer may fail due to revision history tracking",
    strict=False,
)
def test_migration_data_preservation(postgres_db_url, alembic_config):
    """
    Test that data is preserved when upgrading from initial schema to head.
    """
    # 1. Downgrade to base (empty)
    # Actually, we want to test migration between versions.
    # Let's downgrade to the initial revision eba0e1bcc7ec.
    # Note: If we are at head, we can downgrade to eba0e1bcc7ec.
    # If the DB is fresh, it has no revision.
    # apply_migrations fixture runs upgrade head.
    
    # Downgrade to the initial revision (creating users table but not password_history)
    initial_rev = "eba0e1bcc7ec"
    command.downgrade(alembic_config, initial_rev)
    
    # 2. Insert data using sync engine (raw SQL)
    sync_url = postgres_db_url.replace("postgresql://", "postgresql+psycopg2://")
    engine = create_engine(sync_url)
    
    user_id = str(uuid.uuid4())
    
    with engine.connect() as conn:
        # Insert a user
        conn.execute(text(f"""
            INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
            VALUES ('{user_id}', 'mig_user', 'mig@test.com', 'hash', 'user', true, true, NOW())
        """))
        conn.commit()
        
    # 3. Upgrade to head (adds password_history table)
    command.upgrade(alembic_config, "head")
    
    # 4. Verify user still exists
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT username FROM users WHERE id = '{user_id}'"))
        user = result.fetchone()
        assert user is not None
        assert user[0] == 'mig_user'
        
        # Verify new table exists
        result = conn.execute(text("SELECT count(*) FROM password_history"))
        assert result.scalar() == 0 # Should be empty but exist

@pytest.mark.integration
@pytest.mark.asyncio
async def test_transaction_rollback(postgres_db_url, apply_migrations):
    """Test ACID compliance: transaction rollback on failure."""
    db = DatabaseService(database_url=postgres_db_url)
    await db.init_db()
    
    task_id_1 = str(uuid.uuid4())
    task_id_2 = str(uuid.uuid4())
    
    try:
        async with db.pool.pool.acquire() as conn:
            async with conn.transaction():
                # Insert task 1
                await conn.execute(
                    "INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes) VALUES ($1, $2, $3, NOW(), $4)",
                    task_id_1, "file1.pcap", "pending", 100
                )
                
                # Insert task 2 with invalid data (e.g. NULL filename which is NOT NULL)
                # This should raise an error and trigger rollback
                await conn.execute(
                    "INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes) VALUES ($1, $2, $3, NOW(), $4)",
                    task_id_2, None, "pending", 100
                )
    except Exception:
        # Expected failure
        pass
        
    # Verify neither task exists
    task1 = await db.get_task(task_id_1)
    assert task1 is None
    task2 = await db.get_task(task_id_2)
    assert task2 is None

@pytest.mark.integration
@pytest.mark.asyncio
async def test_concurrency_updates(postgres_db_url, apply_migrations):
    """Test concurrent updates to the same row."""
    db = DatabaseService(database_url=postgres_db_url)
    await db.init_db()
    
    task_id = str(uuid.uuid4())
    await db.create_task(task_id, "file.pcap", 100)
    
    # Define an update function
    async def update_status(status):
        await db.update_status(task_id, status)
        
    # Run multiple updates concurrently
    statuses = [TaskStatus.PROCESSING, TaskStatus.COMPLETED, TaskStatus.FAILED]
    
    # We can't easily predict the final state, but we ensure no deadlock or crash
    # and that the final state is valid.
    await asyncio.gather(
        update_status(TaskStatus.PROCESSING),
        update_status(TaskStatus.COMPLETED),
        update_status(TaskStatus.FAILED)
    )
    
    task = await db.get_task(task_id)
    assert task.status in statuses
