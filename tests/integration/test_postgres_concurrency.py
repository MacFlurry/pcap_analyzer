"""
Race condition tests for PostgreSQL (concurrent operations safety).

Tests:
- Concurrent task updates
- Concurrent heartbeat updates
- Concurrent status changes
- Concurrent user deletion (CASCADE safety)
- Deadlock prevention
"""

import pytest
import asyncio
from app.models.schemas import TaskStatus


@pytest.mark.asyncio
async def test_concurrent_task_updates(test_postgres_db):
    """Verify concurrent updates don't cause data corruption."""
    import uuid

    task_id = str(uuid.uuid4())

    # Create task
    await test_postgres_db.create_task(task_id, "test.pcap", 1024)

    # Update status concurrently (10 writers)
    async def update_status(i):
        status = TaskStatus.PROCESSING if i % 2 else TaskStatus.PENDING
        await test_postgres_db.update_status(task_id, status)

    await asyncio.gather(*[update_status(i) for i in range(10)])

    # Verify final status is valid (not corrupted)
    task = await test_postgres_db.get_task(task_id)
    assert task.status in [TaskStatus.PROCESSING, TaskStatus.PENDING]


@pytest.mark.asyncio
async def test_concurrent_heartbeat_updates(test_postgres_db):
    """Verify concurrent heartbeat updates work correctly."""
    import uuid

    task_id = str(uuid.uuid4())

    # Create task
    await test_postgres_db.create_task(task_id, "test.pcap", 1024)

    # Update heartbeat concurrently (20 writers)
    async def update_heartbeat():
        await test_postgres_db.update_heartbeat(task_id, progress_percent=50, current_phase="test")

    await asyncio.gather(*[update_heartbeat() for _ in range(20)])

    # Verify task still exists after concurrent heartbeat updates
    task = await test_postgres_db.get_task(task_id)
    assert task is not None
    assert task.task_id == task_id


@pytest.mark.asyncio
async def test_concurrent_status_changes(test_postgres_db):
    """Verify concurrent status transitions work correctly."""
    import uuid

    # Create 10 tasks
    task_ids = [str(uuid.uuid4()) for i in range(10)]
    for task_id in task_ids:
        await test_postgres_db.create_task(task_id, "test.pcap", 1024)

    # Transition all to "processing" concurrently
    async def transition(task_id):
        await test_postgres_db.update_status(task_id, TaskStatus.PROCESSING)

    await asyncio.gather(*[transition(tid) for tid in task_ids])

    # Verify all tasks transitioned successfully
    for task_id in task_ids:
        task = await test_postgres_db.get_task(task_id)
        assert task.status == TaskStatus.PROCESSING


@pytest.mark.asyncio
async def test_concurrent_user_deletion(test_postgres_db, test_users):
    """Verify concurrent user deletion with CASCADE is safe."""
    import uuid

    # Create tasks for both users
    for i in range(5):
        await test_postgres_db.create_task(
            str(uuid.uuid4()), "test.pcap", 1024,
            owner_id=test_users["user_a"]["id"]
        )
        await test_postgres_db.create_task(
            str(uuid.uuid4()), "test.pcap", 1024,
            owner_id=test_users["user_b"]["id"]
        )

    # Delete both users concurrently
    async def delete_user(user_id):
        await test_postgres_db.pool.execute(
            "DELETE FROM users WHERE id = $1", user_id
        )

    await asyncio.gather(
        delete_user(test_users["user_a"]["id"]),
        delete_user(test_users["user_b"]["id"])
    )

    # Verify ALL tasks deleted (CASCADE)
    remaining_tasks = await test_postgres_db.pool.fetch_all(
        """
        SELECT * FROM tasks
        WHERE owner_id IN ($1, $2)
        """,
        test_users["user_a"]["id"],
        test_users["user_b"]["id"]
    )
    assert len(remaining_tasks) == 0


@pytest.mark.asyncio
async def test_concurrent_updates_no_deadlock(test_postgres_db):
    """Verify concurrent updates don't cause deadlocks."""
    import uuid

    task_id = str(uuid.uuid4())

    # Create task
    await test_postgres_db.create_task(task_id, "test.pcap", 1024)

    # 100 concurrent status updates (stress test)
    async def update_status(i):
        status = [TaskStatus.PENDING, TaskStatus.PROCESSING, TaskStatus.COMPLETED][i % 3]
        await test_postgres_db.update_status(task_id, status)

    # Run concurrently (should not deadlock)
    await asyncio.gather(*[update_status(i) for i in range(100)])

    # Verify task still exists and has valid status
    task = await test_postgres_db.get_task(task_id)
    assert task is not None
    assert task.status in [TaskStatus.PENDING, TaskStatus.PROCESSING, TaskStatus.COMPLETED]
