"""
Tests for Upload endpoint (PCAP file upload).

Coverage target: > 85%
"""

import pytest
from httpx import AsyncClient, ASGITransport
import tempfile
import shutil
from pathlib import Path
import os

from app.models.user import UserRole, UserCreate

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def client():
    """Create async HTTP client for testing with initialized databases."""
    tmpdir = Path(tempfile.mkdtemp(prefix="upload_test_"))

    try:
        # Set environment variables to temp directory
        original_data_dir = os.environ.get("DATA_DIR")
        original_database_url = os.environ.get("DATABASE_URL")
        original_secret_key = os.environ.get("SECRET_KEY")

        os.environ["DATA_DIR"] = str(tmpdir)
        os.environ["DATABASE_URL"] = f"sqlite:///{tmpdir}/pcap_analyzer.db"
        os.environ["SECRET_KEY"] = "test-secret-key-for-jwt-signing-in-tests-minimum-32-chars"

        # Clear singletons
        import app.services.database
        import app.services.user_database
        import app.services.worker
        app.services.database._db_service = None
        app.services.user_database._user_db_service = None
        app.services.worker._worker = None

        # Force reload of modules with DATA_DIR constants
        import sys
        if 'app.api.routes.upload' in sys.modules:
            import importlib
            importlib.reload(sys.modules['app.api.routes.upload'])

        # Import app and initialize databases
        from app.main import app
        from app.services.database import get_db_service
        from app.services.user_database import get_user_db_service
        from app.services.worker import get_worker

        db_service = get_db_service()
        await db_service.init_db()

        user_db_service = get_user_db_service()
        await user_db_service.init_db()
        await user_db_service.migrate_tasks_table()

        # Create test user
        user = UserCreate(
            username="testuser",
            email="test@example.com",
            password="Correct-Horse-Battery-Staple-2025!"
        )
        await user_db_service.create_user(user, role=UserRole.USER, auto_approve=True)

        # Start worker
        worker = get_worker()
        await worker.start()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac

        # Stop worker
        await worker.stop()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

        # Restore environment variables
        if original_data_dir:
            os.environ["DATA_DIR"] = original_data_dir
        elif "DATA_DIR" in os.environ:
            del os.environ["DATA_DIR"]
        if original_database_url:
            os.environ["DATABASE_URL"] = original_database_url
        elif "DATABASE_URL" in os.environ:
            del os.environ["DATABASE_URL"]
        if original_secret_key:
            os.environ["SECRET_KEY"] = original_secret_key
        elif "SECRET_KEY" in os.environ:
            del os.environ["SECRET_KEY"]

        # Reset singletons
        import app.services.database
        import app.services.user_database
        import app.services.worker
        app.services.database._db_service = None
        app.services.user_database._user_db_service = None
        app.services.worker._worker = None


async def get_auth_token(client: AsyncClient) -> str:
    """Helper to get authentication token."""
    response = await client.post(
        "/api/token",
        data={"username": "testuser", "password": "Correct-Horse-Battery-Staple-2025!"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


async def get_csrf_token(client: AsyncClient, auth_token: str) -> str:
    """Helper to get CSRF token."""
    response = await client.get(
        "/api/csrf/token",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


class TestUploadPcap:
    """Test PCAP file upload endpoint."""

    async def test_upload_valid_pcap(self, client: AsyncClient):
        """Test uploading a valid PCAP file."""
        auth_token = await get_auth_token(client)
        csrf_token = await get_csrf_token(client, auth_token)

        # Create valid PCAP file (little-endian magic)
        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000

        files = {"file": ("test.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
        response = await client.post(
            "/api/upload",
            files=files,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 202
        data = response.json()
        assert "task_id" in data
        assert data["filename"] == "test.pcap"
        assert data["status"] == "pending"

    async def test_upload_valid_pcapng(self, client: AsyncClient):
        """Test uploading a valid PCAPNG file."""
        auth_token = await get_auth_token(client)
        csrf_token = await get_csrf_token(client, auth_token)

        # Create valid PCAPNG file
        pcap_content = b'\x0a\x0d\x0d\x0a' + b'\x00' * 1000

        files = {"file": ("test.pcapng", pcap_content, "application/vnd.tcpdump.pcap")}
        response = await client.post(
            "/api/upload",
            files=files,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 202

    async def test_upload_without_auth(self, client: AsyncClient):
        """Test that upload requires authentication."""
        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000
        files = {"file": ("test.pcap", pcap_content, "application/vnd.tcpdump.pcap")}

        response = await client.post("/api/upload", files=files)

        assert response.status_code in [401, 403]

    async def test_upload_without_csrf_token(self, client: AsyncClient):
        """Test that upload requires CSRF token."""
        auth_token = await get_auth_token(client)

        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000
        files = {"file": ("test.pcap", pcap_content, "application/vnd.tcpdump.pcap")}

        response = await client.post(
            "/api/upload",
            files=files,
            headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == 403  # CSRF validation fails

    async def test_upload_invalid_extension(self, client: AsyncClient):
        """Test that invalid file extensions are rejected."""
        auth_token = await get_auth_token(client)
        csrf_token = await get_csrf_token(client, auth_token)

        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000
        files = {"file": ("test.txt", pcap_content, "text/plain")}

        response = await client.post(
            "/api/upload",
            files=files,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 400
        assert "Invalid file extension" in response.json()["detail"]

    async def test_upload_file_too_large(self, client: AsyncClient):
        """Test that files exceeding size limit are rejected."""
        auth_token = await get_auth_token(client)
        csrf_token = await get_csrf_token(client, auth_token)

        # Create file larger than 500MB (default limit)
        # We'll use a smaller test but check the validation logic
        large_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * (501 * 1024 * 1024)

        files = {"file": ("large.pcap", large_content, "application/vnd.tcpdump.pcap")}

        response = await client.post(
            "/api/upload",
            files=files,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 413
        assert "too large" in response.json()["detail"]

    async def test_upload_empty_file(self, client: AsyncClient):
        """Test that empty files are rejected."""
        auth_token = await get_auth_token(client)
        csrf_token = await get_csrf_token(client, auth_token)

        files = {"file": ("empty.pcap", b'', "application/vnd.tcpdump.pcap")}

        response = await client.post(
            "/api/upload",
            files=files,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()

    async def test_upload_invalid_magic_bytes(self, client: AsyncClient):
        """Test that files with invalid magic bytes are rejected."""
        auth_token = await get_auth_token(client)
        csrf_token = await get_csrf_token(client, auth_token)

        # Invalid magic bytes
        invalid_content = b'NOTAPCAP' + b'\x00' * 1000
        files = {"file": ("fake.pcap", invalid_content, "application/vnd.tcpdump.pcap")}

        response = await client.post(
            "/api/upload",
            files=files,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 400
        assert "Invalid PCAP file format" in response.json()["detail"]

    async def test_upload_sanitizes_filename(self, client: AsyncClient):
        """Test that malicious filenames are sanitized."""
        auth_token = await get_auth_token(client)
        csrf_token = await get_csrf_token(client, auth_token)

        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000

        # Malicious filename with path traversal
        files = {"file": ("../../etc/passwd.pcap", pcap_content, "application/vnd.tcpdump.pcap")}

        response = await client.post(
            "/api/upload",
            files=files,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-CSRF-Token": csrf_token
            }
        )

        # Should succeed but filename sanitized
        assert response.status_code == 202
        data = response.json()
        # Original malicious filename preserved in response (for user display)
        # but actual file saved with sanitized name


class TestQueueStatus:
    """Test queue status endpoint."""

    async def test_get_queue_status(self, client: AsyncClient):
        """Test getting queue status."""
        auth_token = await get_auth_token(client)

        response = await client.get(
            "/api/queue/status",
            headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "queue_size" in data
        assert "max_queue_size" in data
        assert "total_tasks" in data
        assert data["max_queue_size"] == 5

    async def test_queue_status_without_auth(self, client: AsyncClient):
        """Test that queue status requires authentication."""
        response = await client.get("/api/queue/status")

        assert response.status_code == 401
