"""
Pytest fixtures et configuration commune pour les tests
"""

import asyncio
import asyncpg
import os
import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient
from passlib.context import CryptContext

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


def get_test_database_url(test_data_dir: Path, db_type: str = "auto") -> str:
    """
    Get database URL for tests.

    Args:
        test_data_dir: Test directory for SQLite database
        db_type: "sqlite", "postgresql", or "auto" (detect from environment)

    Returns:
        Database URL string
    """
    if db_type == "postgresql" or (db_type == "auto" and os.getenv("DATABASE_URL", "").startswith("postgresql")):
        # Use PostgreSQL from environment
        return os.getenv(
            "DATABASE_URL",
            "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test"
        )
    else:
        # Default to SQLite
        db_path = test_data_dir / "test.db"
        return f"sqlite:///{db_path}"


@pytest.fixture
async def test_db(test_data_dir: Path) -> AsyncGenerator[DatabaseService, None]:
    """Create test database (auto-detects SQLite vs PostgreSQL from DATABASE_URL)"""
    database_url = get_test_database_url(test_data_dir, db_type="auto")

    db = DatabaseService(database_url=database_url)
    await db.init_db()
    yield db

    # Cleanup for PostgreSQL (TRUNCATE tables for isolation)
    if database_url.startswith("postgresql"):
        await cleanup_database(db.pool)


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
async def async_client(
    test_data_dir,
    test_postgres_pool,
    monkeypatch
) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client for testing FastAPI endpoints."""
    from app.services import database, worker
    from app.services.database import DatabaseService

    monkeypatch.setenv("DATA_DIR", str(test_data_dir))
    monkeypatch.setenv(
        "DATABASE_URL",
        os.getenv("DATABASE_URL", "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test")
    )

    # Reset singletons
    database._db_service = None
    worker._worker = None

    # CRITICAL: Initialize database before yielding client
    database_url = os.getenv(
        "DATABASE_URL",
        "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test"
    )
    db = DatabaseService(database_url=database_url)
    await db.init_db()

    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

    # Cleanup
    await cleanup_database(db.pool)


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


# =============================================================================
# TCP Packet Fixtures for TCP Handshake Tests
# =============================================================================

@pytest.fixture
def sample_tcp_syn_packet():
    """Create a sample TCP SYN packet"""
    from scapy.all import Ether, IP, TCP

    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, flags="S", seq=1000)
    pkt.time = 1.0
    return pkt


@pytest.fixture
def sample_tcp_synack_packet():
    """Create a sample TCP SYN-ACK packet"""
    from scapy.all import Ether, IP, TCP

    pkt = Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
    pkt.time = 1.05
    return pkt


@pytest.fixture
def sample_tcp_ack_packet():
    """Create a sample TCP ACK packet"""
    from scapy.all import Ether, IP, TCP

    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)
    pkt.time = 1.10
    return pkt


@pytest.fixture
def tcp_handshake_packets(sample_tcp_syn_packet, sample_tcp_synack_packet, sample_tcp_ack_packet):
    """Create a complete TCP handshake (SYN, SYN-ACK, ACK)"""
    return [sample_tcp_syn_packet, sample_tcp_synack_packet, sample_tcp_ack_packet]


@pytest.fixture
def sample_ipv6_packet():
    """Create a sample IPv6 TCP SYN packet"""
    from scapy.all import Ether, IPv6, TCP

    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=12345, dport=80, flags="S", seq=1000)
    pkt.time = 1.0
    return pkt


@pytest.fixture
def sample_tcp_packet():
    """Alias for sample_tcp_syn_packet - generic TCP packet"""
    from scapy.all import Ether, IP, TCP

    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, flags="S", seq=1000)
    pkt.time = 1.0
    return pkt


@pytest.fixture
def sample_tcp_fin_packet():
    """Create a sample TCP FIN packet"""
    from scapy.all import Ether, IP, TCP

    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, flags="F", seq=1000)
    pkt.time = 1.0
    return pkt


@pytest.fixture
def sample_tcp_rst_packet():
    """Create a sample TCP RST packet"""
    from scapy.all import Ether, IP, TCP

    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, flags="R", seq=1000)
    pkt.time = 1.0
    return pkt


@pytest.fixture
def sample_tcp_data_packet():
    """Create a sample TCP packet with data payload"""
    from scapy.all import Ether, IP, TCP, Raw

    pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=2000) / Raw(load=b"Test data")
    pkt.time = 1.0
    return pkt


# =============================================================================
# PostgreSQL Integration Test Fixtures
# =============================================================================


@pytest.fixture(scope="session")
async def ensure_postgres_ready():
    """Wait for PostgreSQL to be ready (max 30s)."""
    url = os.getenv(
        "DATABASE_URL",
        "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test"
    )

    for attempt in range(30):
        try:
            conn = await asyncpg.connect(url)
            await conn.close()
            return  # PostgreSQL ready
        except Exception:
            await asyncio.sleep(1)

    raise RuntimeError("PostgreSQL not ready after 30s")


async def cleanup_database(pool):
    """Truncate all tables for test isolation (fast and reliable)."""
    try:
        await pool.execute("""
            TRUNCATE TABLE progress_snapshots, tasks, users
            RESTART IDENTITY CASCADE
        """)
    except Exception:
        # Tables might not exist (e.g., after migration downgrade test)
        pass


@pytest.fixture(scope="session")
async def test_postgres_pool(ensure_postgres_ready):
    """PostgreSQL connection pool fixture (SHARED across all tests)."""
    from app.services.postgres_database import DatabasePool

    database_url = os.getenv(
        "DATABASE_URL",
        "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test"
    )

    pool = DatabasePool(database_url=database_url)
    await pool.connect()

    yield pool

    # Cleanup: close pool ONCE at end of session
    await pool.close()


@pytest.fixture(scope="function")
async def test_postgres_db(test_postgres_pool):
    """PostgreSQL DatabaseService fixture with TRUNCATE-based isolation."""
    from app.services.database import DatabaseService

    database_url = os.getenv(
        "DATABASE_URL",
        "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test"
    )

    db = DatabaseService(database_url=database_url)

    # Run migrations (idempotent)
    await db.init_db()

    yield db

    # Cleanup: TRUNCATE all tables
    await cleanup_database(db.pool)


@pytest.fixture
async def test_users(test_postgres_db):
    """Create test users for multi-tenant and CASCADE DELETE tests."""
    import uuid

    users = {
        "user_a": {
            "id": str(uuid.uuid4()),
            "username": "user_a",
            "email": "a@test.com",
            "hashed_password": "hashed_password_123",
            "role": "user",
            "is_active": True,
            "is_approved": True,
        },
        "user_b": {
            "id": str(uuid.uuid4()),
            "username": "user_b",
            "email": "b@test.com",
            "hashed_password": "hashed_password_123",
            "role": "user",
            "is_active": True,
            "is_approved": True,
        },
        "admin": {
            "id": str(uuid.uuid4()),
            "username": "admin",
            "email": "admin@test.com",
            "hashed_password": "hashed_admin_123",
            "role": "admin",
            "is_active": True,
            "is_approved": True,
        },
    }

    # Insert users
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for user_data in users.values():
        await test_postgres_db.pool.execute(
            """
            INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            user_data["id"],
            user_data["username"],
            user_data["email"],
            user_data["hashed_password"],
            user_data["role"],
            user_data["is_active"],
            user_data["is_approved"],
            now,
        )

    return users  # Return for easy access: test_users["user_a"]["id"]
