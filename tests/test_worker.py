"""
Tests for Worker service (analysis queue management).

Coverage target: > 80%
"""

import asyncio
import pytest
from pathlib import Path
import tempfile
import os
import shutil
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.worker import AnalysisWorker
from app.models.schemas import TaskStatus

pytestmark = pytest.mark.asyncio


@pytest.fixture
def temp_data_dir():
    """Create a temporary data directory for tests."""
    tmpdir = Path(tempfile.mkdtemp(prefix="worker_test_"))

    # Set environment variable to temp directory
    original_data_dir = os.environ.get("DATA_DIR")
    os.environ["DATA_DIR"] = str(tmpdir)

    # Clear singletons to force recreation with new DATA_DIR
    import app.services.analyzer
    import app.services.database
    import app.services.user_database
    app.services.analyzer._analyzer_service = None
    app.services.database._db_service = None
    app.services.user_database._user_db_service = None

    try:
        yield tmpdir
    finally:
        # Cleanup
        shutil.rmtree(tmpdir, ignore_errors=True)

        # Restore environment variable
        if original_data_dir:
            os.environ["DATA_DIR"] = original_data_dir
        elif "DATA_DIR" in os.environ:
            del os.environ["DATA_DIR"]

        # Reset singletons again
        app.services.analyzer._analyzer_service = None
        app.services.database._db_service = None
        app.services.user_database._user_db_service = None


@pytest.fixture
def mock_db_service():
    """Create a mock database service."""
    mock = AsyncMock()
    mock.update_status = AsyncMock()
    mock.update_heartbeat = AsyncMock()
    mock.create_progress_snapshot = AsyncMock()
    mock.update_results = AsyncMock()
    return mock


@pytest.fixture
def mock_analyzer_service():
    """Create a mock analyzer service."""
    mock = AsyncMock()
    mock.analyze_pcap = AsyncMock(return_value={
        "results": {
            "metadata": {"total_packets": 100},
            "health_score": {"overall_score": 0.85}
        },
        "reports": {
            "html": "/data/reports/test.html",
            "json": "/data/reports/test.json"
        }
    })
    return mock


class TestAnalysisWorker:
    """Test AnalysisWorker queue management."""

    async def test_worker_init(self, temp_data_dir, mock_db_service, mock_analyzer_service):
        """Test worker initialization."""
        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        assert worker.queue.maxsize == 5
        assert worker.get_queue_size() == 0
        assert not worker.is_running

    async def test_worker_start_stop(self, temp_data_dir, mock_db_service, mock_analyzer_service):
        """Test worker start/stop lifecycle."""
        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        # Start worker
        await worker.start()
        assert worker.is_running

        # Stop worker
        await worker.stop()
        assert not worker.is_running

    async def test_enqueue_task(self, temp_data_dir, mock_db_service, mock_analyzer_service, tmp_path):
        """Test enqueueing a task."""
        # Create temp PCAP file
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000)

        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        # Don't start worker to avoid actual processing
        # Just test enqueue mechanism
        task_id = "test-task-123"
        success = await worker.enqueue(task_id, str(pcap_file))

        assert success is True
        assert worker.get_queue_size() == 1

    async def test_queue_full_rejection(self, temp_data_dir, mock_db_service, mock_analyzer_service, tmp_path):
        """Test that queue rejects tasks when full."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000)

        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            max_queue_size=3,  # Use smaller queue for faster testing
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        # Fill queue (don't start worker to prevent processing)
        for i in range(3):
            task_id = f"task-{i}"
            success = await worker.enqueue(task_id, str(pcap_file))
            assert success is True

        # Queue should be full now
        assert worker.get_queue_size() == 3

        # Next enqueue should fail
        success = await worker.enqueue("task-overflow", str(pcap_file))
        assert success is False

    async def test_get_queue_size(self, temp_data_dir, mock_db_service, mock_analyzer_service):
        """Test getting queue size."""
        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        size = worker.get_queue_size()
        assert size == 0
        assert isinstance(size, int)

    async def test_start_when_already_running(self, temp_data_dir, mock_db_service, mock_analyzer_service):
        """Test that starting an already-running worker logs warning."""
        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        await worker.start()
        assert worker.is_running

        # Try to start again - should log warning but not fail
        await worker.start()
        assert worker.is_running

        await worker.stop()

    async def test_stop_when_not_running(self, temp_data_dir, mock_db_service, mock_analyzer_service):
        """Test that stopping a non-running worker is safe."""
        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        # Should not fail
        await worker.stop()
        assert not worker.is_running

    async def test_progress_updates_tracking(self, temp_data_dir, mock_db_service, mock_analyzer_service):
        """Test progress update storage and retrieval."""
        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        task_id = "test-task-456"

        # Initially no updates
        updates = worker.get_progress_updates(task_id)
        assert updates == []

        # Add update manually (simulating internal tracking)
        from app.services.worker import ProgressUpdate
        update = ProgressUpdate(
            task_id=task_id,
            phase="parsing",
            progress_percent=25,
            packets_processed=250,
            total_packets=1000
        )
        worker.progress_updates[task_id].append(update)

        # Should retrieve the update
        updates = worker.get_progress_updates(task_id)
        assert len(updates) == 1
        assert updates[0].phase == "parsing"
        assert updates[0].progress_percent == 25

        # Clear updates
        worker.clear_progress_updates(task_id)
        updates = worker.get_progress_updates(task_id)
        assert updates == []

    async def test_progress_update_timestamp_default(self, temp_data_dir, mock_db_service, mock_analyzer_service):
        """Test that ProgressUpdate sets timestamp if not provided."""
        from app.services.worker import ProgressUpdate
        from datetime import datetime, timezone

        # Create update without timestamp
        update = ProgressUpdate(
            task_id="test",
            phase="test",
            progress_percent=50
        )

        # Should have auto-generated timestamp
        assert update.timestamp is not None
        assert isinstance(update.timestamp, datetime)

    async def test_should_persist_progress(self, temp_data_dir, mock_db_service, mock_analyzer_service):
        """Test _should_persist_progress logic."""
        worker = AnalysisWorker(
            data_dir=str(temp_data_dir),
            db_service=mock_db_service,
            analyzer_service=mock_analyzer_service
        )

        task_id = "test-persist"

        # First update should persist
        assert worker._should_persist_progress(task_id, 0) is True

        # Record that 0 was persisted
        worker._last_persisted_progress[task_id] = 0

        # 1% shouldn't persist (not multiple of 5)
        assert worker._should_persist_progress(task_id, 1) is False

        # 5% should persist
        assert worker._should_persist_progress(task_id, 5) is True
        worker._last_persisted_progress[task_id] = 5

        # Same 5% shouldn't persist again
        assert worker._should_persist_progress(task_id, 5) is False

        # 10% should persist
        assert worker._should_persist_progress(task_id, 10) is True
        worker._last_persisted_progress[task_id] = 10

        # 100% should always persist
        assert worker._should_persist_progress(task_id, 100) is True
