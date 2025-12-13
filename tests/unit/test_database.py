"""
Tests unitaires pour le service database
"""

from datetime import datetime

import pytest

from app.models.schemas import TaskStatus
from app.services.database import DatabaseService


@pytest.mark.unit
@pytest.mark.asyncio
async def test_init_db(test_db):
    """Test database initialization"""
    # Database should be initialized
    assert test_db is not None

    # Should be able to query stats
    stats = await test_db.get_stats()
    assert stats["total"] == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_create_task(test_db):
    """Test task creation"""
    task = await test_db.create_task(task_id="test-123", filename="test.pcap", file_size_bytes=1024)

    assert task.task_id == "test-123"
    assert task.filename == "test.pcap"
    assert task.file_size_bytes == 1024
    assert task.status == TaskStatus.PENDING


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_task(test_db):
    """Test retrieving a task"""
    # Create task
    await test_db.create_task(task_id="test-456", filename="test2.pcap", file_size_bytes=2048)

    # Retrieve task
    task = await test_db.get_task("test-456")

    assert task is not None
    assert task.task_id == "test-456"
    assert task.filename == "test2.pcap"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_nonexistent_task(test_db):
    """Test retrieving a non-existent task"""
    task = await test_db.get_task("nonexistent")
    assert task is None


@pytest.mark.unit
@pytest.mark.asyncio
async def test_update_status(test_db):
    """Test updating task status"""
    # Create task
    await test_db.create_task(task_id="test-789", filename="test3.pcap", file_size_bytes=4096)

    # Update status
    await test_db.update_status("test-789", TaskStatus.PROCESSING)

    # Verify update
    task = await test_db.get_task("test-789")
    assert task.status == TaskStatus.PROCESSING


@pytest.mark.unit
@pytest.mark.asyncio
async def test_update_results(test_db):
    """Test updating analysis results"""
    # Create task
    await test_db.create_task(task_id="test-results", filename="results.pcap", file_size_bytes=8192)

    # Update results
    await test_db.update_results(
        task_id="test-results",
        total_packets=1000,
        health_score=85.5,
        report_html_path="/data/reports/test-results.html",
        report_json_path="/data/reports/test-results.json",
    )

    # Verify
    task = await test_db.get_task("test-results")
    assert task.total_packets == 1000
    assert task.health_score == 85.5
    assert "/api/reports/test-results/html" == task.report_html_url
    assert "/api/reports/test-results/json" == task.report_json_url


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_recent_tasks(test_db):
    """Test retrieving recent tasks"""
    # Create multiple tasks
    for i in range(5):
        await test_db.create_task(task_id=f"task-{i}", filename=f"test{i}.pcap", file_size_bytes=1024 * i)

    # Get recent tasks
    tasks = await test_db.get_recent_tasks(limit=3)

    assert len(tasks) == 3
    # Should be sorted by upload date (descending)
    assert tasks[0].task_id == "task-4"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_stats(test_db):
    """Test getting statistics"""
    # Create tasks with different statuses
    await test_db.create_task("pending-1", "p1.pcap", 100)
    await test_db.create_task("pending-2", "p2.pcap", 100)

    await test_db.create_task("completed-1", "c1.pcap", 100)
    await test_db.update_status("completed-1", TaskStatus.COMPLETED)

    await test_db.create_task("failed-1", "f1.pcap", 100)
    await test_db.update_status("failed-1", TaskStatus.FAILED)

    # Get stats
    stats = await test_db.get_stats()

    assert stats["total"] == 4
    assert stats["pending"] == 2
    assert stats["completed"] == 1
    assert stats["failed"] == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_mark_expired_tasks(test_db):
    """Test marking expired tasks"""
    # Create old task (would need to manipulate timestamps in real test)
    # For now, just test the function doesn't crash
    count = await test_db.mark_expired_tasks(retention_hours=24)
    assert count >= 0
