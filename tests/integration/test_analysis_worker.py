"""
Tests d'intégration pour l'AnalysisWorker.
"""

import asyncio
import pytest
import uuid
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path
from datetime import datetime, timezone

from app.services.worker import AnalysisWorker
from app.services.analyzer import AnalyzerService
from app.models.schemas import TaskStatus

@pytest.fixture
def mock_analyzer_service():
    """Create a mock analyzer service."""
    service = AsyncMock(spec=AnalyzerService)
    return service

@pytest.fixture
async def worker(test_db, mock_analyzer_service, test_data_dir):
    """Create an AnalysisWorker instance with mocked analyzer."""
    worker = AnalysisWorker(
        max_queue_size=5,
        data_dir=str(test_data_dir),
        db_service=test_db,
        analyzer_service=mock_analyzer_service
    )
    await worker.start()
    yield worker
    await worker.stop()

@pytest.mark.integration
@pytest.mark.asyncio
async def test_worker_processing_success(worker, test_db, test_data_dir, mock_analyzer_service, auth_user):
    """
    Test standard success cycle: PENDING -> PROCESSING -> COMPLETED.
    """
    task_id = str(uuid.uuid4())
    pcap_path = test_data_dir / "test.pcap"
    pcap_path.write_bytes(b"dummy pcap content")
    
    # Setup mock returns
    mock_analyzer_service.analyze_pcap.return_value = {
        "results": {
            "metadata": {"total_packets": 100},
            "health_score": {"overall_score": 90.0}
        },
        "reports": {
            "html": str(test_data_dir / "report.html"),
            "json": str(test_data_dir / "report.json")
        }
    }
    
    # 1. Create task in DB as pending
    await test_db.create_task(
        task_id=task_id,
        filename="test.pcap",
        file_size_bytes=100,
        owner_id=auth_user.id
    )
    
    # 2. Enqueue task
    await worker.enqueue(task_id, str(pcap_path))
    
    # 3. Wait for processing (polling status)
    for _ in range(10):
        task = await test_db.get_task(task_id)
        if task.status == TaskStatus.COMPLETED:
            break
        await asyncio.sleep(0.5)
    
    assert task.status == TaskStatus.COMPLETED
    assert task.total_packets == 100
    assert task.health_score == 90.0
    
    # 4. Verify PCAP was deleted
    assert not pcap_path.exists()

@pytest.mark.integration
@pytest.mark.asyncio
async def test_worker_processing_failure(worker, test_db, test_data_dir, mock_analyzer_service, auth_user):
    """
    Test failure cycle: PENDING -> PROCESSING -> FAILED.
    """
    task_id = str(uuid.uuid4())
    pcap_path = test_data_dir / "test_fail.pcap"
    pcap_path.write_bytes(b"dummy pcap content")
    
    # Setup mock to raise error
    mock_analyzer_service.analyze_pcap.side_effect = Exception("Analyse a échoué lamentablement")
    
    # 1. Create task in DB
    await test_db.create_task(
        task_id=task_id,
        filename="test_fail.pcap",
        file_size_bytes=100,
        owner_id=auth_user.id
    )
    
    # 2. Enqueue task
    await worker.enqueue(task_id, str(pcap_path))
    
    # 3. Wait for failure
    for _ in range(10):
        task = await test_db.get_task(task_id)
        if task.status == TaskStatus.FAILED:
            break
        await asyncio.sleep(0.5)
    
    assert task.status == TaskStatus.FAILED
    assert "échoué lamentablement" in task.error_message

@pytest.mark.integration
@pytest.mark.asyncio
async def test_worker_cleanup_logic(test_data_dir):
    """
    Test file cleanup logic (simulated since it's usually handled by a scheduler).
    Note: Real cleanup is in app/services/cleanup.py.
    This test focuses on what the worker does after task completion.
    """
    # The post-processing cleanup is verified in test_worker_processing_success (pcap_path.exists() == False)
    pass
