"""
Pytest fixtures et configuration commune pour les tests
"""

import os
import tempfile

# Unconditionally set DATA_DIR for tests to ensure it's writeable
os.environ["DATA_DIR"] = os.path.join(tempfile.gettempdir(), "pcap_analyzer_test")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{os.path.join(os.environ['DATA_DIR'], 'test.db')}")

import asyncio
import asyncpg
import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from fastapi_csrf_protect import CsrfProtect
from httpx import AsyncClient, ASGITransport
from passlib.context import CryptContext
from testcontainers.postgres import PostgresContainer
from alembic.config import Config
from alembic import command

# Remove top-level app import
# from app.main import app
from app.models.user import User, UserRole
from app.auth import get_current_user, get_current_user_sse
from app.services.analyzer import ProgressCallback
from app.services.database import DatabaseService
from app.services.user_database import UserDatabaseService
from app.services.worker import AnalysisWorker


# =============================================================================
# Pytest Configuration for Dual-Database Testing (Issue #26 Phase 2)
# =============================================================================


def pytest_configure(config):
    """Register custom markers for dual-database testing."""
    config.addinivalue_line(
        "markers", "db_parametrize: Run test against both SQLite and PostgreSQL (auto-parametrized)"
    )


def pytest_generate_tests(metafunc):
    """
    Auto-parametrize tests marked with @pytest.mark.db_parametrize.

    Tests with 'db_type' in their signature will be run twice:
    - Once with db_type="sqlite"
    - Once with db_type="postgresql"

    The test_db fixture will automatically use the correct database based on db_type.
    """
    if "db_type" in metafunc.fixturenames and metafunc.definition.get_closest_marker("db_parametrize"):
        metafunc.parametrize("db_type", ["sqlite", "postgresql"])


# =============================================================================
# Test Fixtures
# =============================================================================


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


@pytest.fixture(scope="session")
def postgres_container():
    """
    Spins up a PostgreSQL container for integration tests.
    Returns the connection URL.
    """
    # Use postgres:15-alpine to match production recommendation
    with PostgresContainer("postgres:15-alpine") as postgres:
        # testcontainers waits for the container to be ready

        # Get connection URL
        db_url = postgres.get_connection_url()

        # Ensure compatibility with asyncpg (used by the app)
        if db_url.startswith("postgresql+psycopg2://"):
            async_db_url = db_url.replace("postgresql+psycopg2://", "postgresql://")
        else:
            async_db_url = db_url

        yield async_db_url


@pytest.fixture(scope="session")
def postgres_db_url(postgres_container):
    """
    Sets the DATABASE_URL environment variable to the container's URL.
    This ensures that any code reading os.environ["DATABASE_URL"] gets the test container.
    """
    os.environ["DATABASE_URL"] = postgres_container
    return postgres_container


@pytest.fixture(scope="session")
def apply_migrations(postgres_db_url):
    """
    Applies Alembic migrations to the test container.
    """
    # Create Alembic configuration
    alembic_cfg = Config("alembic.ini")

    # Override the sqlalchemy.url in the configuration
    # We need to use the sync driver (psycopg2) for Alembic
    sync_url = postgres_db_url.replace("postgresql://", "postgresql+psycopg2://")
    alembic_cfg.set_main_option("sqlalchemy.url", sync_url)

    # Run migrations
    command.upgrade(alembic_cfg, "head")

    yield


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
        return os.getenv("DATABASE_URL", "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test")
    else:
        # Default to SQLite
        db_path = test_data_dir / "test.db"
        return f"sqlite:///{db_path}"


@pytest.fixture
async def test_db(
    test_data_dir: Path, request, postgres_db_url, apply_migrations, test_postgres_pool
) -> AsyncGenerator[DatabaseService, None]:
    """
    Create test database (auto-detects SQLite vs PostgreSQL from DATABASE_URL).

    Supports dual-database testing via @pytest.mark.db_parametrize:
    - If test has db_type parameter, uses that to select database
    - Otherwise auto-detects from DATABASE_URL environment variable
    """
    # Check if test is parametrized with db_type
    db_type = "auto"
    if hasattr(request, "param"):
        db_type = request.param
    elif "db_type" in request.fixturenames:
        # Get db_type from parametrized test argument
        db_type = request.getfixturevalue("db_type")

    database_url = ""
    db = None
    if db_type == "postgresql" or (db_type == "auto" and os.getenv("DATABASE_URL", "").startswith("postgresql")):
        # Use postgres fixtures
        database_url = postgres_db_url

        # Use shared pool
        db = DatabaseService(database_url=database_url)
        db.pool = test_postgres_pool
    else:
        database_url = get_test_database_url(test_data_dir, db_type=db_type)
        db = DatabaseService(database_url=database_url)

    await db.init_db()

    # Create mock admin user to satisfy foreign key constraints
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    try:
        # Use direct SQL to satisfy foreign key constraints with a fixed ID
        # that matches the one used in the client fixture
        query, params = db.pool.translate_query(
            """
            INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("00000000-0000-0000-0000-000000000000", "admin-test", "admin@test.com", "hash", "admin", True, True, now),
        )
        await db.pool.execute(query, *params)
    except Exception:
        # User might already exist (e.g. from init_db or previous run)
        pass

    yield db

    # Cleanup for PostgreSQL (TRUNCATE tables for isolation)
    if database_url.startswith("postgresql"):
        await cleanup_database(db.pool)
    else:
        # Close SQLite pool
        await db.pool.close()


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
def client(test_data_dir: Path, monkeypatch, request) -> Generator[TestClient, None, None]:
    """Create test client for FastAPI"""
    from app.main import app

    # Set DATA_DIR to temporary directory for tests
    monkeypatch.setenv("DATA_DIR", str(test_data_dir))

    # Determine database URL (same logic as test_db)
    db_type = "auto"
    if "db_type" in request.fixturenames:
        db_type = request.getfixturevalue("db_type")

    if db_type == "postgresql" or (db_type == "auto" and os.getenv("DATABASE_URL", "").startswith("postgresql")):
        # Request postgres fixtures
        database_url = request.getfixturevalue("postgres_db_url")
        request.getfixturevalue("apply_migrations")
    else:
        database_url = get_test_database_url(test_data_dir, db_type=db_type)

    monkeypatch.setenv("DATABASE_URL", database_url)

    # Patch DATA_DIR in all modules that define it at module level
    # from app.api.routes import health, reports, upload
    # Note: These modules now use dynamic config via app.utils.config,
    # so we don't need to patch module attributes anymore.
    # The setenv above is sufficient.

    # Reset all singletons to pick up new DATA_DIR and ensure clean state
    from app.services import database, worker, user_database, postgres_database, analyzer

    database._db_service = None
    worker._worker = None
    user_database._user_db_service = None
    postgres_database._db_pool = None
    analyzer._analyzer_service = None

    # Mock get_worker to return a MockWorker that doesn't actually process tasks
    # This prevents event loop issues and real PCAP analysis from running
    def mock_get_worker():
        if worker._worker is None:
            worker._worker = MockWorker(data_dir=str(test_data_dir))
        return worker._worker

    monkeypatch.setattr(worker, "get_worker", mock_get_worker)

    # Also patch where it was already imported
    from app import main as app_main
    from app.api.routes import upload, health

    monkeypatch.setattr(app_main, "get_worker", mock_get_worker)
    monkeypatch.setattr(upload, "get_worker", mock_get_worker)
    monkeypatch.setattr(health, "get_worker", mock_get_worker)

    # Mock authentication
    mock_admin = User(
        id="00000000-0000-0000-0000-000000000000",
        username="admin",
        email="admin@test.com",
        hashed_password="hash",
        role=UserRole.ADMIN,
        is_active=True,
        is_approved=True,
    )
    app.dependency_overrides[get_current_user] = lambda: mock_admin
    app.dependency_overrides[get_current_user_sse] = lambda: mock_admin

    # Mock CSRF
    from unittest.mock import MagicMock

    mock_csrf = MagicMock()
    mock_csrf.validate_csrf = AsyncMock(return_value=None)
    mock_csrf.generate_csrf_tokens = MagicMock(return_value=("mock-token", "mock-signed-token"))
    app.dependency_overrides[CsrfProtect] = lambda: mock_csrf

    with TestClient(app) as test_client:
        yield test_client

    # Cleanup: reset worker singleton and overrides
    app.dependency_overrides = {}
    worker._worker = None


@pytest.fixture
async def async_client(
    test_data_dir, monkeypatch, request, postgres_db_url, apply_migrations, test_postgres_pool
) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client for testing FastAPI endpoints."""
    from app.main import app
    from app.services import database, worker, user_database, postgres_database, analyzer

    monkeypatch.setenv("DATA_DIR", str(test_data_dir))

    # Determine database URL
    db_type = "auto"
    if "db_type" in request.fixturenames:
        db_type = request.getfixturevalue("db_type")

    if db_type == "postgresql" or (db_type == "auto" and os.getenv("DATABASE_URL", "").startswith("postgresql")):
        # Use postgres fixtures
        database_url = postgres_db_url
    else:
        database_url = get_test_database_url(test_data_dir, db_type=db_type)

    monkeypatch.setenv("DATABASE_URL", database_url)

    # Reset singletons
    database._db_service = None
    worker._worker = None
    user_database._user_db_service = None
    postgres_database._db_pool = None
    analyzer._analyzer_service = None

    # Patch DATA_DIR
    # from app.api.routes import health, reports, upload
    # Note: Using dynamic config now.

    # Mock get_worker
    def mock_get_worker():
        if worker._worker is None:
            worker._worker = MockWorker(data_dir=str(test_data_dir))
        return worker._worker

    monkeypatch.setattr(worker, "get_worker", mock_get_worker)

    # Also patch where it was already imported
    from app import main as app_main
    from app.api.routes import upload, health

    monkeypatch.setattr(app_main, "get_worker", mock_get_worker)
    monkeypatch.setattr(upload, "get_worker", mock_get_worker)
    monkeypatch.setattr(health, "get_worker", mock_get_worker)

    # Mock authentication
    mock_admin = User(
        id="00000000-0000-0000-0000-000000000000",
        username="admin",
        email="admin@test.com",
        hashed_password="hash",
        role=UserRole.ADMIN,
        is_active=True,
        is_approved=True,
    )
    app.dependency_overrides[get_current_user] = lambda: mock_admin
    app.dependency_overrides[get_current_user_sse] = lambda: mock_admin

    # Mock CSRF
    from unittest.mock import MagicMock

    mock_csrf = MagicMock()
    mock_csrf.validate_csrf = AsyncMock(return_value=None)
    mock_csrf.generate_csrf_tokens = MagicMock(return_value=("mock-token", "mock-signed-token"))
    app.dependency_overrides[CsrfProtect] = lambda: mock_csrf

    # Initialize databases
    db = DatabaseService(database_url=database_url)
    if db_type == "postgresql" or (db_type == "auto" and os.getenv("DATABASE_URL", "").startswith("postgresql")):
        db.pool = test_postgres_pool

    await db.init_db()
    database._db_service = db

    udb = UserDatabaseService(database_url=database_url)
    await udb.init_db()
    user_database._user_db_service = udb

    # Create mock admin user
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    try:
        query, params = db.pool.translate_query(
            """
            INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("00000000-0000-0000-0000-000000000000", "admin-test", "admin@test.com", "hash", "admin", True, True, now),
        )
        await db.pool.execute(query, *params)
    except Exception:
        pass

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    # Cleanup
    app.dependency_overrides = {}
    if db.pool and not (
        db_type == "postgresql" or (db_type == "auto" and os.environ.get("DATABASE_URL", "").startswith("postgresql"))
    ):
        await db.pool.close()
    worker._worker = None


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

    pkt = (
        Ether() / IP(src="192.168.1.2", dst="192.168.1.1") / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
    )
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

    pkt = (
        Ether()
        / IP(src="192.168.1.1", dst="192.168.1.2")
        / TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=2000)
        / Raw(load=b"Test data")
    )
    pkt.time = 1.0
    return pkt


# =============================================================================
# PostgreSQL Integration Test Fixtures
# =============================================================================


@pytest.fixture(scope="session")
async def ensure_postgres_ready():
    """Wait for PostgreSQL to be ready (max 30s)."""
    url = os.getenv("DATABASE_URL", "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test")

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
        await pool.execute(
            """
            TRUNCATE TABLE progress_snapshots, tasks, users
            RESTART IDENTITY CASCADE
        """
        )
    except Exception:
        # Tables might not exist (e.g., after migration downgrade test)
        pass


@pytest.fixture(scope="session")
async def test_postgres_pool(postgres_db_url, ensure_postgres_ready):
    """PostgreSQL connection pool fixture (SHARED across all tests)."""
    from app.services.postgres_database import DatabasePool

    pool = DatabasePool(database_url=postgres_db_url)
    await pool.connect()

    yield pool

    # Cleanup: close pool ONCE at end of session
    await pool.close()


@pytest.fixture(scope="function")
async def test_postgres_db(test_postgres_pool):
    """PostgreSQL DatabaseService fixture with TRUNCATE-based isolation."""
    from app.services.database import DatabaseService

    database_url = os.getenv(
        "DATABASE_URL", "postgresql://pcap:change_me_in_production@localhost:5432/pcap_analyzer_test"
    )

    db = DatabaseService(database_url=database_url)

    # Run migrations (idempotent)
    await db.init_db()

    yield db

    # Cleanup: TRUNCATE all tables
    await cleanup_database(db.pool)
    await db.pool.close()


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
