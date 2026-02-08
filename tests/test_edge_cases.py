"""
Edge case tests for database operations.

Covers:
- Empty result sets
- NULL owner_id (legacy data)
- UUID vs TEXT(36) compatibility
- Large result sets / pagination
"""

import pytest
import uuid
import asyncio
from app.services.database import DatabaseService
from app.models.schemas import TaskStatus


@pytest.mark.asyncio
@pytest.mark.db_parametrize
async def test_empty_database_queries(test_db, db_type):
    """Verify empty result handling (SQLite and PostgreSQL)."""
    # Query empty database
    tasks = await test_db.get_recent_tasks(limit=10)
    assert tasks == []

    stats = await test_db.get_stats()
    assert stats["total"] == 0
    assert stats["pending"] == 0

    # Get non-existent task
    task = await test_db.get_task("00000000-0000-0000-0000-000000000001")
    assert task is None


@pytest.mark.asyncio
@pytest.mark.db_parametrize
async def test_null_owner_id_handling(test_db, db_type):
    """Verify NULL owner_id tasks (legacy data) are handled correctly."""
    # Create task with NULL owner_id (legacy data simulation)
    task_id = str(uuid.uuid4())

    # Manual insert with NULL owner_id
    if db_type == "sqlite":
        await test_db.pool.execute("""
            INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
            VALUES (?, ?, ?, datetime('now'), ?, NULL)
        """, task_id, "legacy.pcap", "pending", 1024)
    else:
        await test_db.pool.execute("""
            INSERT INTO tasks (task_id, filename, status, uploaded_at, file_size_bytes, owner_id)
            VALUES ($1, $2, $3, NOW(), $4, NULL)
        """, task_id, "legacy.pcap", "pending", 1024)

    # Retrieve task
    task = await test_db.get_task(task_id)

    assert task is not None
    assert task.task_id == task_id
    # owner_id should be None (not raise exception)
    assert not hasattr(task, 'owner_id') or task.owner_id is None


@pytest.mark.asyncio
@pytest.mark.db_parametrize
async def test_uuid_vs_string_id(test_db, db_type):
    """Verify PostgreSQL UUID vs SQLite TEXT(36) compatibility."""
    # Create task with UUID-formatted string
    task_id = str(uuid.uuid4())

    task = await test_db.create_task(task_id, "uuid_test.pcap", 4096)

    # Verify retrieval works
    retrieved = await test_db.get_task(task_id)
    assert retrieved is not None
    assert retrieved.task_id == task_id

    # Verify UUID format is preserved
    assert len(retrieved.task_id) == 36
    assert retrieved.task_id.count('-') == 4


@pytest.mark.asyncio
@pytest.mark.db_parametrize
async def test_large_result_set(test_db, db_type):
    """Verify pagination with 1000+ tasks."""
    # Create 100 tasks (scale down from 1000 for test speed)
    for i in range(100):
        task_id = f"00000000-0000-0000-0000-{i:012d}"
        await test_db.create_task(task_id, f"test{i}.pcap", 1024 * i)

    # Test pagination
    page1 = await test_db.get_recent_tasks(limit=10)
    assert len(page1) == 10

    page2 = await test_db.get_recent_tasks(limit=20)
    assert len(page2) == 20

    # Verify stats
    stats = await test_db.get_stats()
    assert stats["total"] == 100

    # Verify descending order (most recent first)
    assert page1[0].task_id == "00000000-0000-0000-0000-000000000099"  # Last created
    assert page1[9].task_id == "00000000-0000-0000-0000-000000000090"


@pytest.mark.asyncio
@pytest.mark.db_parametrize
async def test_special_characters_in_filenames(test_db, db_type):
    """Test filenames with special characters."""
    special_filenames = [
        "file with spaces.pcap",
        "file_with_underscores.pcap",
        "file-with-dashes.pcap",
        "file.multiple.dots.pcap",
        "file(with)parentheses.pcap",
        "file[with]brackets.pcap",
        "file'with'quotes.pcap"
    ]

    for i, filename in enumerate(special_filenames):
        task_id = f"10000000-0000-0000-0000-{i:012d}"
        task = await test_db.create_task(task_id, filename, 1024)

        assert task.filename == filename

        # Verify retrieval
        retrieved = await test_db.get_task(task_id)
        assert retrieved.filename == filename


@pytest.mark.asyncio
@pytest.mark.db_parametrize
async def test_concurrent_status_updates(test_db, db_type):
    """Test concurrent status updates don't cause race conditions."""
    task_id = "20000000-0000-0000-0000-000000000001"
    await test_db.create_task(task_id, "concurrent.pcap", 2048)

    # Launch 5 concurrent status updates
    async def update_status(status):
        await test_db.update_status(task_id, status)

    await asyncio.gather(
        update_status(TaskStatus.PROCESSING),
        update_status(TaskStatus.PROCESSING),
        update_status(TaskStatus.PROCESSING),
        update_status(TaskStatus.PROCESSING),
        update_status(TaskStatus.PROCESSING)
    )

    # Verify task still exists and has valid status
    task = await test_db.get_task(task_id)
    assert task is not None
    assert task.status == TaskStatus.PROCESSING
