"""
Pytest fixtures et configuration commune pour les tests
"""

import asyncio
import os
import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

# Import app
from app.main import app
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
    from app.api.routes import upload, reports, health
    monkeypatch.setattr(upload, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(upload, "UPLOADS_DIR", test_data_dir / "uploads")
    monkeypatch.setattr(reports, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(reports, "REPORTS_DIR", test_data_dir / "reports")
    monkeypatch.setattr(health, "DATA_DIR", test_data_dir)

    # Reset DatabaseService singleton to pick up the new DATA_DIR
    from app.services import database
    database._db_service = None

    # Reset Worker singleton as well
    from app.services import worker
    worker._worker = None

    with TestClient(app) as test_client:
        yield test_client


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
