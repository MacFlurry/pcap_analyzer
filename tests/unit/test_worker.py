"""
Tests unitaires pour le worker
"""

import pytest
from pathlib import Path

from app.services.worker import AnalysisWorker, ProgressUpdate
from app.models.schemas import TaskStatus


@pytest.mark.unit
@pytest.mark.asyncio
async def test_worker_initialization(test_data_dir, test_db):
    """Test worker initialization"""
    worker = AnalysisWorker(
        max_queue_size=5,
        data_dir=str(test_data_dir),
        db_service=test_db
    )
    
    assert worker.get_queue_size() == 0
    assert worker.is_running == False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_worker_start_stop(test_worker):
    """Test starting and stopping worker"""
    assert test_worker.is_running == True
    
    await test_worker.stop()
    assert test_worker.is_running == False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_worker_enqueue(test_worker, sample_pcap_file):
    """Test enqueueing a task"""
    task_id = "test-enqueue-123"
    
    success = await test_worker.enqueue(task_id, str(sample_pcap_file))
    
    assert success == True
    assert test_worker.get_queue_size() == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_worker_queue_full(test_worker, sample_pcap_file):
    """Test que la queue refuse quand elle est pleine"""
    # Remplir la queue
    for i in range(5):
        await test_worker.enqueue(f"task-{i}", str(sample_pcap_file))
    
    # Essayer d'ajouter un 6ème
    success = await test_worker.enqueue("task-overflow", str(sample_pcap_file))
    
    assert success == False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_progress_updates_storage(test_worker):
    """Test storage of progress updates"""
    task_id = "test-progress-123"
    
    # Ajouter des updates
    update = ProgressUpdate(
        task_id=task_id,
        phase="metadata",
        progress_percent=50,
        packets_processed=1000,
        total_packets=2000
    )
    
    test_worker.progress_updates[task_id].append(update)
    
    # Récupérer les updates
    updates = test_worker.get_progress_updates(task_id)
    
    assert len(updates) == 1
    assert updates[0].phase == "metadata"
    assert updates[0].progress_percent == 50


@pytest.mark.unit
@pytest.mark.asyncio
async def test_clear_progress_updates(test_worker):
    """Test clearing progress updates"""
    task_id = "test-clear-123"
    
    # Ajouter un update
    test_worker.progress_updates[task_id].append(
        ProgressUpdate(task_id=task_id, phase="test", progress_percent=0)
    )
    
    # Clear
    test_worker.clear_progress_updates(task_id)
    
    # Vérifier
    updates = test_worker.get_progress_updates(task_id)
    assert len(updates) == 0
