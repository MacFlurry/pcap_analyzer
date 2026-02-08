"""
CASCADE DELETE tests for PostgreSQL (data integrity protection).

Tests foreign key CASCADE DELETE constraints:
- tasks.owner_id → users.id (CASCADE)
- progress_snapshots.task_id → tasks.task_id (CASCADE)

Verifies:
- User deletion cascades to tasks
- Task deletion cascades to progress snapshots
- CASCADE preserves other users' data
- Orphaned tasks (owner_id=NULL) survive deletion
- CASCADE constraints exist in schema
"""

import os
import uuid
import asyncpg
import pytest


# Use function-scoped pool to avoid event loop issues
@pytest.fixture
async def db_pool(postgres_db_url, apply_migrations):
    """Create a fresh connection pool for each test."""
    database_url = postgres_db_url
    if not database_url.startswith("postgresql://") and not database_url.startswith("postgres://"):
        pytest.skip("PostgreSQL CASCADE tests require DATABASE_URL with postgresql://")
    pool = await asyncpg.create_pool(database_url, min_size=2, max_size=10)

    yield pool

    # Cleanup: truncate tables and close pool
    await pool.execute("TRUNCATE TABLE progress_snapshots, tasks, users RESTART IDENTITY CASCADE")
    await pool.close()


@pytest.fixture
async def test_users(db_pool):
    """Create test users."""
    # Simple password hash (not secure, but sufficient for testing)
    simple_hash = "hashed_password"

    users = {
        "user_a": {
            "id": str(uuid.uuid4()),
            "username": "user_a",
            "email": "a@test.com",
            "hashed_password": simple_hash,
            "role": "user",
            "is_active": True,
            "is_approved": True,
        },
        "user_b": {
            "id": str(uuid.uuid4()),
            "username": "user_b",
            "email": "b@test.com",
            "hashed_password": simple_hash,
            "role": "user",
            "is_active": True,
            "is_approved": True,
        },
        "admin": {
            "id": str(uuid.uuid4()),
            "username": "admin",
            "email": "admin@test.com",
            "hashed_password": simple_hash,
            "role": "admin",
            "is_active": True,
            "is_approved": True,
        },
    }

    # Insert users
    for user_data in users.values():
        await db_pool.execute(
            """
            INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            """,
            user_data["id"],
            user_data["username"],
            user_data["email"],
            user_data["hashed_password"],
            user_data["role"],
            user_data["is_active"],
            user_data["is_approved"],
        )

    return users


@pytest.mark.asyncio
async def test_delete_user_cascades_to_tasks(db_pool, test_users):
    """Verify deleting user cascades to all their tasks."""
    # Create tasks for both users
    task_ids_a = []
    for i in range(3):
        task_id = str(uuid.uuid4())
        task_ids_a.append(task_id)
        await db_pool.execute(
            """
            INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
            VALUES ($1, $2, $3, NOW(), $4, $5)
            """,
            task_id, "test.pcap", "pending", 1024, test_users["user_a"]["id"]
        )

    for i in range(2):
        await db_pool.execute(
            """
            INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
            VALUES ($1, $2, $3, NOW(), $4, $5)
            """,
            str(uuid.uuid4()), "test.pcap", "pending", 1024, test_users["user_b"]["id"]
        )

    # Delete user A
    await db_pool.execute(
        "DELETE FROM users WHERE id = $1",
        test_users["user_a"]["id"]
    )

    # Verify user A's tasks deleted
    tasks_a = await db_pool.fetch(
        "SELECT * FROM tasks WHERE owner_id = $1",
        test_users["user_a"]["id"]
    )
    assert len(tasks_a) == 0

    # Verify user B's tasks remain
    tasks_b = await db_pool.fetch(
        "SELECT * FROM tasks WHERE owner_id = $1",
        test_users["user_b"]["id"]
    )
    assert len(tasks_b) == 2


@pytest.mark.asyncio
async def test_delete_task_cascades_to_progress_snapshots(db_pool):
    """Verify deleting task cascades to all progress snapshots."""
    task_id = str(uuid.uuid4())

    # Create task
    await db_pool.execute(
        """
        INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes)
        VALUES ($1, $2, $3, NOW(), $4)
        """,
        task_id, "test.pcap", "pending", 1024
    )

    # Create 5 progress snapshots
    for i in range(5):
        await db_pool.execute(
            """
            INSERT INTO progress_snapshots (task_id, phase, progress_percent, packets_processed, timestamp)
            VALUES ($1, $2, $3, $4, NOW())
            """,
            task_id, "analysis", i * 20, i * 100
        )

    # Delete task
    await db_pool.execute(
        "DELETE FROM tasks WHERE task_id = $1", task_id
    )

    # Verify ALL snapshots deleted
    snapshots = await db_pool.fetch(
        "SELECT * FROM progress_snapshots WHERE task_id = $1", task_id
    )
    assert len(snapshots) == 0


@pytest.mark.asyncio
async def test_cascade_preserves_other_users_data(db_pool, test_users):
    """Verify CASCADE DELETE preserves other users' data."""
    # Create multiple users with tasks
    total_tasks = 0

    # User A: 3 tasks
    for i in range(3):
        await db_pool.execute(
            """
            INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
            VALUES ($1, $2, $3, NOW(), $4, $5)
            """,
            str(uuid.uuid4()), "test.pcap", "pending", 1024, test_users["user_a"]["id"]
        )
        total_tasks += 1

    # User B: 5 tasks
    for i in range(5):
        await db_pool.execute(
            """
            INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
            VALUES ($1, $2, $3, NOW(), $4, $5)
            """,
            str(uuid.uuid4()), "test.pcap", "pending", 1024, test_users["user_b"]["id"]
        )
        total_tasks += 1

    # Admin: 2 tasks
    for i in range(2):
        await db_pool.execute(
            """
            INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
            VALUES ($1, $2, $3, NOW(), $4, $5)
            """,
            str(uuid.uuid4()), "test.pcap", "pending", 1024, test_users["admin"]["id"]
        )
        total_tasks += 1

    # Delete user A
    await db_pool.execute(
        "DELETE FROM users WHERE id = $1",
        test_users["user_a"]["id"]
    )

    # Verify total tasks: 10 - 3 = 7
    remaining_tasks = await db_pool.fetch("SELECT * FROM tasks")
    assert len(remaining_tasks) == 7


@pytest.mark.asyncio
async def test_orphaned_tasks_handling(db_pool):
    """Verify tasks with owner_id=NULL survive user deletion."""
    system_task_id = str(uuid.uuid4())
    user_task_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())

    # Create system task (no owner)
    await db_pool.execute(
        """
        INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
        VALUES ($1, $2, $3, NOW(), $4, $5)
        """,
        system_task_id, "system.pcap", "pending", 1024, None
    )

    # Create user task
    await db_pool.execute(
        """
        INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        """,
        user_id, "tempuser", "temp@example.com", "hashed", "user", True, True
    )

    await db_pool.execute(
        """
        INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
        VALUES ($1, $2, $3, NOW(), $4, $5)
        """,
        user_task_id, "user.pcap", "pending", 1024, user_id
    )

    # Delete user
    await db_pool.execute("DELETE FROM users WHERE id = $1", user_id)

    # Verify system task remains
    system_task = await db_pool.fetchrow("SELECT * FROM tasks WHERE task_id = $1", system_task_id)
    assert system_task is not None

    # Verify user task deleted
    user_task = await db_pool.fetchrow("SELECT * FROM tasks WHERE task_id = $1", user_task_id)
    assert user_task is None


@pytest.mark.asyncio
async def test_cascade_constraints_exist(db_pool):
    """Verify CASCADE DELETE foreign keys are defined in schema."""
    constraints = await db_pool.fetch("""
        SELECT conname, confdeltype, conrelid::regclass AS table_name
        FROM pg_constraint
        WHERE confrelid IN ('users'::regclass, 'tasks'::regclass)
    """)

    # Find owner_id CASCADE constraint
    owner_fk = next((c for c in constraints if "owner_id" in c["conname"]), None)
    assert owner_fk is not None
    # confdeltype is returned as bytes in asyncpg, 'c' = CASCADE
    assert owner_fk["confdeltype"] == b"c" or owner_fk["confdeltype"] == "c"

    # Find task_id CASCADE constraint
    task_fk = next((c for c in constraints if "task_id" in c["conname"] and c["table_name"] == "progress_snapshots"), None)
    assert task_fk is not None
    # confdeltype is returned as bytes in asyncpg, 'c' = CASCADE
    assert task_fk["confdeltype"] == b"c" or task_fk["confdeltype"] == "c"


@pytest.mark.asyncio
async def test_progress_snapshots_cascade_multi_level(db_pool, test_users):
    """Verify CASCADE works across multiple levels (user → task → snapshots)."""
    user_id = test_users["user_a"]["id"]

    # Create task for user
    task_id = str(uuid.uuid4())
    await db_pool.execute(
        """
        INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
        VALUES ($1, $2, $3, NOW(), $4, $5)
        """,
        task_id, "test.pcap", "pending", 1024, user_id
    )

    # Create 3 progress snapshots
    for i in range(3):
        await db_pool.execute(
            """
            INSERT INTO progress_snapshots (task_id, phase, progress_percent, packets_processed, timestamp)
            VALUES ($1, $2, $3, $4, NOW())
            """,
            task_id, "analysis", i * 33, i * 100
        )

    # Delete user (should cascade to task, then to snapshots)
    await db_pool.execute("DELETE FROM users WHERE id = $1", user_id)

    # Verify task deleted
    task = await db_pool.fetchrow("SELECT * FROM tasks WHERE task_id = $1", task_id)
    assert task is None

    # Verify snapshots deleted
    snapshots = await db_pool.fetch(
        "SELECT * FROM progress_snapshots WHERE task_id = $1", task_id
    )
    assert len(snapshots) == 0
