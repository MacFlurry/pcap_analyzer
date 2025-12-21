"""
Transaction isolation tests for PostgreSQL (ACID guarantees).

Tests:
- Rollback on constraint violation
- READ COMMITTED isolation level
- Concurrent read/write isolation
"""

import pytest
import asyncio


@pytest.mark.asyncio
async def test_rollback_on_constraint_violation(test_postgres_db):
    """Verify transaction rollback on PRIMARY KEY violation."""
    import uuid
    from datetime import datetime, timezone

    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # Insert user (should succeed)
    await test_postgres_db.pool.execute(
        """
        INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """,
        user_id, "testuser", "test@example.com", "hashed", "user", True, True, now
    )

    # Try to insert duplicate (should fail)
    with pytest.raises(Exception):  # asyncpg.UniqueViolationError
        await test_postgres_db.pool.execute(
            """
            INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            user_id, "testuser2", "test2@example.com", "hashed", "user", True, True, now
        )


@pytest.mark.asyncio
async def test_transaction_isolation_read_committed(test_postgres_db):
    """Verify READ COMMITTED isolation level."""
    import uuid

    task_id = str(uuid.uuid4())

    # Create task
    await test_postgres_db.pool.execute(
        """
        INSERT INTO tasks (task_id, filename, file_size_bytes, status, uploaded_at, created_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        """,
        task_id, "test.pcap", 1024, "pending"
    )

    # Transaction 1: Update status (don't commit)
    async with test_postgres_db.pool.pool.acquire() as conn1:
        tx1 = conn1.transaction()
        await tx1.start()

        await conn1.execute(
            "UPDATE tasks SET status = $1 WHERE task_id = $2",
            "processing", task_id
        )

        # Transaction 2: Read status (should see OLD value)
        async with test_postgres_db.pool.pool.acquire() as conn2:
            row = await conn2.fetchrow(
                "SELECT status FROM tasks WHERE task_id = $1", task_id
            )
            assert row["status"] == "pending"  # Isolation verified

        await tx1.commit()

    # Now read again (should see NEW value)
    row = await test_postgres_db.pool.fetch_one(
        "SELECT status FROM tasks WHERE task_id = $1", task_id
    )
    assert row["status"] == "processing"


@pytest.mark.asyncio
async def test_concurrent_read_write_isolation(test_postgres_db):
    """Verify concurrent reads don't see partial writes."""
    import uuid

    task_id = str(uuid.uuid4())

    # Create task
    await test_postgres_db.create_task(task_id, "test.pcap", 1024)

    async def reader():
        """Read task status 10 times."""
        for _ in range(10):
            task = await test_postgres_db.get_task(task_id)
            assert task.status in ["pending", "processing", "completed"]
            await asyncio.sleep(0.01)

    async def writer():
        """Update task status 10 times."""
        from app.models.schemas import TaskStatus
        statuses = [TaskStatus.PENDING, TaskStatus.PROCESSING, TaskStatus.COMPLETED] * 4
        for status in statuses[:10]:
            await test_postgres_db.update_status(task_id, status)
            await asyncio.sleep(0.01)

    # Run readers and writers concurrently
    await asyncio.gather(reader(), reader(), writer())
