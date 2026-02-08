"""
Tests for HTML template views.

Coverage target: 100%
"""

import pytest
from httpx import AsyncClient, ASGITransport

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


class TestViews:
    """Test HTML template views."""

    async def test_index_page(self, client: AsyncClient):
        """Test that index page loads."""
        response = await client.get("/", follow_redirects=True)

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "<!DOCTYPE html>" in response.text or "<html" in response.text

    async def test_progress_page(self, client: AsyncClient):
        """Test that progress page loads with task_id."""
        task_id = "test-task-123"
        response = await client.get(f"/progress/{task_id}", follow_redirects=True)

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        # Task ID is injected by JavaScript, just verify page loads

    async def test_history_page(self, client: AsyncClient):
        """Test that history page loads."""
        response = await client.get("/history", follow_redirects=True)

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    async def test_login_page(self, client: AsyncClient):
        """Test that login page loads."""
        response = await client.get("/login")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    async def test_logout_page(self, client: AsyncClient):
        """Test that logout page loads."""
        response = await client.get("/logout")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    async def test_admin_page(self, client: AsyncClient):
        """Test that admin page loads."""
        response = await client.get("/admin", follow_redirects=True)

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    async def test_change_password_page(self, client: AsyncClient):
        """Test that change-password page loads."""
        response = await client.get("/change-password", follow_redirects=True)

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
