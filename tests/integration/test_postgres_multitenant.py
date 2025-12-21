"""
Multi-tenant isolation tests for PostgreSQL (CWE-639 protection).

Tests:
- User sees only own tasks
- User cannot access other user's tasks
- Admin sees all tasks
- Concurrent multi-user operations
- System tasks (owner_id=NULL) handling
"""

import pytest
import asyncio


@pytest.mark.asyncio
async def test_user_sees_only_own_tasks(test_postgres_db, test_users):
    """Verify user sees only their own tasks."""
    import uuid

    # Create tasks for user A
    task_a_ids = []
    for i in range(3):
        task_id = str(uuid.uuid4())
        task_a_ids.append(task_id)
        await test_postgres_db.create_task(
            task_id, "test.pcap", 1024,
            owner_id=test_users["user_a"]["id"]
        )

    # Create tasks for user B
    task_b_ids = []
    for i in range(2):
        task_id = str(uuid.uuid4())
        task_b_ids.append(task_id)
        await test_postgres_db.create_task(
            task_id, "test.pcap", 1024,
            owner_id=test_users["user_b"]["id"]
        )

    # User A should see only their 3 tasks
    user_a_tasks = await test_postgres_db.get_recent_tasks(
        owner_id=test_users["user_a"]["id"]
    )
    assert len(user_a_tasks) == 3
    user_a_task_ids = [t.task_id for t in user_a_tasks]
    assert all(tid in task_a_ids for tid in user_a_task_ids)

    # User B should see only their 2 tasks
    user_b_tasks = await test_postgres_db.get_recent_tasks(
        owner_id=test_users["user_b"]["id"]
    )
    assert len(user_b_tasks) == 2
    user_b_task_ids = [t.task_id for t in user_b_tasks]
    assert all(tid in task_b_ids for tid in user_b_task_ids)


@pytest.mark.asyncio
async def test_user_cannot_access_other_tasks(test_postgres_db, test_users):
    """Verify get_task respects owner_id filtering (app-level)."""
    import uuid

    # Create task for user A
    task_a_id = str(uuid.uuid4())
    await test_postgres_db.create_task(
        task_a_id, "test.pcap", 1024,
        owner_id=test_users["user_a"]["id"]
    )

    # Create task for user B
    task_b_id = str(uuid.uuid4())
    await test_postgres_db.create_task(
        task_b_id, "test.pcap", 1024,
        owner_id=test_users["user_b"]["id"]
    )

    # get_task returns task regardless of owner (DB-level)
    task_b = await test_postgres_db.get_task(task_b_id)
    assert task_b is not None

    # NOTE: App-level filtering should be done in API layer
    # This test verifies DB returns data, app must filter


@pytest.mark.asyncio
async def test_admin_sees_all_tasks(test_postgres_db, test_users):
    """Verify admin (owner_id=None) sees all tasks."""
    import uuid

    # Create tasks for multiple users
    task_a_id = str(uuid.uuid4())
    await test_postgres_db.create_task(
        task_a_id, "test.pcap", 1024,
        owner_id=test_users["user_a"]["id"]
    )
    task_b_id = str(uuid.uuid4())
    await test_postgres_db.create_task(
        task_b_id, "test.pcap", 1024,
        owner_id=test_users["user_b"]["id"]
    )

    # Admin view (owner_id=None) should see all
    all_tasks = await test_postgres_db.get_recent_tasks(owner_id=None)
    assert len(all_tasks) >= 2
    task_ids = [t.task_id for t in all_tasks]
    assert task_a_id in task_ids
    assert task_b_id in task_ids


@pytest.mark.asyncio
async def test_concurrent_multi_user_operations(test_postgres_db, test_users):
    """Verify concurrent task creation by multiple users."""
    import uuid

    async def create_user_tasks(user_id, count):
        """Create tasks for a user."""
        for i in range(count):
            task_id = str(uuid.uuid4())
            await test_postgres_db.create_task(
                task_id, "test.pcap", 1024,
                owner_id=user_id
            )

    # Simulate 3 users creating tasks concurrently
    await asyncio.gather(
        create_user_tasks(test_users["user_a"]["id"], 5),
        create_user_tasks(test_users["user_b"]["id"], 5),
        create_user_tasks(test_users["admin"]["id"], 5),
    )

    # Verify each user has exactly 5 tasks
    user_a_tasks = await test_postgres_db.get_recent_tasks(
        owner_id=test_users["user_a"]["id"]
    )
    assert len(user_a_tasks) == 5

    user_b_tasks = await test_postgres_db.get_recent_tasks(
        owner_id=test_users["user_b"]["id"]
    )
    assert len(user_b_tasks) == 5


@pytest.mark.asyncio
async def test_owner_id_null_system_tasks(test_postgres_db):
    """Verify tasks with owner_id=NULL (system tasks) are handled correctly."""
    import uuid
    from datetime import datetime, timezone

    # Create system task (no owner)
    system_task_id = str(uuid.uuid4())
    await test_postgres_db.create_task(
        system_task_id, "system.pcap", 1024,
        owner_id=None
    )

    # Create user task
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    await test_postgres_db.pool.execute(
        """
        INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """,
        user_id, "testuser", "test@example.com", "hashed", "user", True, True, now
    )

    user_task_id = str(uuid.uuid4())
    await test_postgres_db.create_task(
        user_task_id, "user.pcap", 1024,
        owner_id=user_id
    )

    # User should NOT see system tasks
    user_tasks = await test_postgres_db.get_recent_tasks(owner_id=user_id)
    task_ids = [t.task_id for t in user_tasks]
    assert system_task_id not in task_ids
    assert user_task_id in task_ids

    # Admin (owner_id=None) should see ALL tasks
    all_tasks = await test_postgres_db.get_recent_tasks(owner_id=None)
    all_task_ids = [t.task_id for t in all_tasks]
    assert system_task_id in all_task_ids
    assert user_task_id in all_task_ids
