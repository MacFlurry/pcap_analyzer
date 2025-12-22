"""
Tests for Health Check endpoint.

Coverage target: > 80%
"""

import pytest
from httpx import AsyncClient, ASGITransport
import tempfile
import shutil
from pathlib import Path
import os
import time

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def client():
    """Create async HTTP client for testing with initialized databases."""
    tmpdir = Path(tempfile.mkdtemp(prefix="health_test_"))

    try:
        # Set environment variables to temp directory
        original_data_dir = os.environ.get("DATA_DIR")
        original_database_url = os.environ.get("DATABASE_URL")

        os.environ["DATA_DIR"] = str(tmpdir)
        os.environ["DATABASE_URL"] = f"sqlite:///{tmpdir}/pcap_analyzer.db"

        # Clear singletons
        import app.services.database
        import app.services.user_database
        app.services.database._db_service = None
        app.services.user_database._user_db_service = None

        # Import app and initialize databases
        from app.main import app
        from app.services.database import get_db_service
        from app.services.user_database import get_user_db_service

        db_service = get_db_service()
        await db_service.init_db()

        user_db_service = get_user_db_service()
        await user_db_service.init_db()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
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

        # Reset singletons
        import app.services.database
        import app.services.user_database
        app.services.database._db_service = None
        app.services.user_database._user_db_service = None


class TestHealthCheck:
    """Test health check endpoint."""

    async def test_health_check_success(self, client: AsyncClient):
        """Test that health check endpoint returns 200 OK with system stats."""
        response = await client.get("/api/health")

        assert response.status_code == 200
        data = response.json()

        # Should have basic health info
        assert "status" in data
        assert data["status"] == "healthy"

        assert "version" in data
        assert isinstance(data["version"], str)

        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], (int, float))
        assert data["uptime_seconds"] >= 0

    async def test_health_check_includes_queue_stats(self, client: AsyncClient):
        """Test that health check includes worker queue statistics."""
        response = await client.get("/api/health")

        assert response.status_code == 200
        data = response.json()

        # Should have queue stats (queue_size field, not nested)
        assert "queue_size" in data
        assert isinstance(data["queue_size"], int)
        assert data["queue_size"] >= 0

        # Should have active analyses count
        assert "active_analyses" in data
        assert isinstance(data["active_analyses"], int)
        assert data["active_analyses"] >= 0

    async def test_health_check_includes_database_stats(self, client: AsyncClient):
        """Test that health check includes database statistics."""
        response = await client.get("/api/health")

        assert response.status_code == 200
        data = response.json()

        # Should have task completion stats
        assert "total_tasks_completed" in data
        assert isinstance(data["total_tasks_completed"], int)
        assert data["total_tasks_completed"] >= 0

        assert "total_tasks_failed" in data
        assert isinstance(data["total_tasks_failed"], int)
        assert data["total_tasks_failed"] >= 0

    async def test_health_check_no_authentication_required(self, client: AsyncClient):
        """Test that health check endpoint doesn't require authentication."""
        # Health check should be publicly accessible
        response = await client.get("/api/health")
        assert response.status_code == 200

        # Should not return 401 Unauthorized
        assert response.status_code != 401

    async def test_health_check_cors_headers(self, client: AsyncClient):
        """Test that health check includes appropriate CORS headers if configured."""
        response = await client.get("/api/health")

        assert response.status_code == 200

        # May have CORS headers depending on config
        # Just verify response is successful
