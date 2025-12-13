"""
Pytest fixtures et configuration commune pour les tests
"""

import asyncio
import os
import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

# Import app
from app.main import app
from app.services.analyzer import ProgressCallback
from app.services.database import DatabaseService
from app.services.worker import AnalysisWorker


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_data_dir() -> Generator[Path, None, None]:
    """Create temporary data directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir)
        (data_dir / "uploads").mkdir()
        (data_dir / "reports").mkdir()
        yield data_dir


class MockAnalyzerService:
    """Mock analyzer service that returns dummy results instantly"""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.reports_dir = self.data_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    async def analyze_pcap(
        self,
        task_id: str,
        pcap_path: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> dict[str, Any]:
        """Mock analyze_pcap that returns dummy results instantly"""
        # Send progress updates if callback provided
        if progress_callback:
            await progress_callback.update("initialization", 0, message="Starting analysis")
            await progress_callback.update("analysis", 50, message="Analyzing packets")
            await progress_callback.update("reporting", 100, message="Generating reports")

        # Create dummy report files
        html_path = self.reports_dir / f"{task_id}.html"
        json_path = self.reports_dir / f"{task_id}.json"

        html_path.write_text("<html><body>Mock Report</body></html>")
        json_path.write_text('{"mock": true, "health_score": {"overall_score": 100.0}}')

        return {
            "results": {
                "metadata": {"total_packets": 0},
                "health_score": {"overall_score": 100.0},
            },
            "reports": {
                "html": str(html_path),
                "json": str(json_path),
            },
        }


class MockWorker(AnalysisWorker):
    """Mock worker that doesn't actually process tasks, just accepts them"""

    def __init__(self, data_dir: str):
        # Don't call super().__init__() to avoid creating real queue/analyzer
        self.data_dir = Path(data_dir)
        self.is_running = False
        self._queue_size = 0
        self.queue = asyncio.Queue(maxsize=5)  # Create queue for compatibility
        self.progress_updates = {}
        self.worker_task = None

    async def start(self):
        """Mock start - doesn't actually start a worker loop"""
        self.is_running = True

    async def stop(self):
        """Mock stop"""
        self.is_running = False

    async def enqueue(self, task_id: str, pcap_path: str) -> bool:
        """Mock enqueue - just accepts the task without processing"""
        self._queue_size += 1
        # Don't actually add to queue to avoid processing
        return True

    def get_queue_size(self) -> int:
        """Return mock queue size"""
        return self._queue_size

    def get_progress_updates(self, task_id: str) -> list:
        """Return empty progress updates"""
        return self.progress_updates.get(task_id, [])


@pytest.fixture
def mock_analyzer(test_data_dir: Path) -> MockAnalyzerService:
    """Create mock analyzer service"""
    return MockAnalyzerService(data_dir=str(test_data_dir))


@pytest.fixture
async def test_db(test_data_dir: Path) -> AsyncGenerator[DatabaseService, None]:
    """Create test database"""
    db_path = test_data_dir / "test.db"
    db = DatabaseService(db_path=str(db_path))
    await db.init_db()
    yield db


@pytest.fixture
async def test_worker(test_data_dir: Path, test_db: DatabaseService) -> AsyncGenerator[AnalysisWorker, None]:
    """Create test worker"""
    worker = AnalysisWorker(
        max_queue_size=5,
        data_dir=str(test_data_dir),
        db_service=test_db,
        analyzer_service=None,  # Mock analyzer in tests
    )
    await worker.start()
    yield worker
    await worker.stop()


@pytest.fixture
def client(test_data_dir: Path, monkeypatch) -> Generator[TestClient, None, None]:
    """Create test client for FastAPI"""
    # Set DATA_DIR to temporary directory for tests
    monkeypatch.setenv("DATA_DIR", str(test_data_dir))

    # Patch DATA_DIR in all modules that define it at module level
    from app.api.routes import health, reports, upload

    monkeypatch.setattr(upload, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(upload, "UPLOADS_DIR", test_data_dir / "uploads")
    monkeypatch.setattr(reports, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(reports, "REPORTS_DIR", test_data_dir / "reports")
    monkeypatch.setattr(health, "DATA_DIR", test_data_dir)

    # Reset DatabaseService singleton to pick up the new DATA_DIR
    from app.services import database

    database._db_service = None

    # Reset Worker singleton
    from app.services import worker

    worker._worker = None

    # Mock get_worker to return a MockWorker that doesn't actually process tasks
    # This prevents event loop issues and real PCAP analysis from running
    def mock_get_worker():
        if worker._worker is None:
            worker._worker = MockWorker(data_dir=str(test_data_dir))
        return worker._worker

    monkeypatch.setattr(worker, "get_worker", mock_get_worker)

    with TestClient(app) as test_client:
        yield test_client

    # Cleanup: reset worker singleton
    worker._worker = None


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Create async test client"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def sample_pcap_file(test_data_dir: Path) -> Path:
    """Create a minimal valid PCAP file for testing"""
    pcap_file = test_data_dir / "sample.pcap"

    # PCAP global header (little-endian)
    # Magic number: 0xa1b2c3d4
    # Version: 2.4
    # Timezone: 0
    # Sigfigs: 0
    # Snaplen: 65535
    # Network: 1 (Ethernet)
    global_header = bytes.fromhex(
        "d4c3b2a1"  # Magic
        "0200"  # Major version
        "0400"  # Minor version
        "00000000"  # Timezone
        "00000000"  # Sigfigs
        "ffff0000"  # Snaplen
        "01000000"  # Network (Ethernet)
    )

    pcap_file.write_bytes(global_header)
    return pcap_file


@pytest.fixture
def invalid_pcap_file(test_data_dir: Path) -> Path:
    """Create an invalid PCAP file (wrong magic bytes)"""
    invalid_file = test_data_dir / "invalid.pcap"
    invalid_file.write_bytes(b"INVALID_HEADER_DATA")
    return invalid_file


@pytest.fixture
def large_file(test_data_dir: Path) -> Path:
    """Create a file larger than max upload size"""
    large_file = test_data_dir / "large.pcap"
    # Create 501 MB file (over 500 MB limit)
    size = 501 * 1024 * 1024
    with open(large_file, "wb") as f:
        f.write(b"\x00" * size)
    return large_file
