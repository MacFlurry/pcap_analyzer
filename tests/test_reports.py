"""
Tests for Reports endpoints (HTML and JSON report access).

Coverage target: > 70%
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
    tmpdir = Path(tempfile.mkdtemp(prefix="reports_test_"))

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
        app.services.database._db_service = None
        app.services.user_database._user_db_service = None

        # Force reload of modules with DATA_DIR constants
        import sys
        if 'app.api.routes.reports' in sys.modules:
            import importlib
            importlib.reload(sys.modules['app.api.routes.reports'])

        # Import app and initialize databases
        from app.main import app
        from app.services.database import get_db_service
        from app.services.user_database import get_user_db_service

        db_service = get_db_service()
        await db_service.init_db()

        user_db_service = get_user_db_service()
        await user_db_service.init_db()
        await user_db_service.migrate_tasks_table()

        # Create test admin user
        admin_user = UserCreate(
            username="admin",
            email="admin@example.com",
            password="Correct-Horse-Battery-Staple-2025!"
        )
        admin = await user_db_service.create_user(admin_user, role=UserRole.ADMIN, auto_approve=True)

        # Create test regular user
        user1 = UserCreate(
            username="user1",
            email="user1@example.com",
            password="userpass1234"
        )
        user = await user_db_service.create_user(user1, role=UserRole.USER, auto_approve=True)

        # Create test task for admin
        task1_id = "550e8400-e29b-41d4-a716-446655440001"
        await db_service.create_task(
            task_id=task1_id,
            filename="test1.pcap",
            file_size_bytes=1000,
            owner_id=admin.id
        )

        # Create test task for user1
        task2_id = "550e8400-e29b-41d4-a716-446655440002"
        await db_service.create_task(
            task_id=task2_id,
            filename="test2.pcap",
            file_size_bytes=2000,
            owner_id=user.id
        )

        # Create reports directory and sample reports
        reports_dir = tmpdir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Create HTML report for task1
        html_content = "<html><body>Test Report</body></html>"
        (reports_dir / f"{task1_id}.html").write_text(html_content)

        # Create JSON report for task1
        json_content = '{"test": "data"}'
        (reports_dir / f"{task1_id}.json").write_text(json_content)

        # Create reports for task2
        (reports_dir / f"{task2_id}.html").write_text(html_content)
        (reports_dir / f"{task2_id}.json").write_text(json_content)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac, admin.id, user.id, task1_id, task2_id
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
        app.services.database._db_service = None
        app.services.user_database._user_db_service = None


async def get_auth_token(client: AsyncClient, username: str, password: str) -> str:
    """Helper to get authentication token."""
    response = await client.post(
        "/api/token",
        data={"username": username, "password": password}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


class TestGetHTMLReport:
    """Test GET /reports/{task_id}/html endpoint."""

    async def test_get_html_report_with_valid_token(self, client):
        """Test that owner can access their HTML report."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        response = await ac.get(
            f"/api/reports/{task1_id}/html",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Test Report" in response.text

    async def test_get_html_report_with_token_in_query_param(self, client):
        """Test that HTML report can be accessed via query param token (browser compatibility)."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        response = await ac.get(f"/api/reports/{task1_id}/html?token={token}")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    async def test_get_html_report_not_found(self, client):
        """Test accessing non-existent report."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        # Task doesn't exist
        response = await ac.get(
            "/api/reports/550e8400-e29b-41d4-a716-446655440999/html",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 404

    async def test_get_html_report_access_denied(self, client):
        """Test that user cannot access other user's report."""
        ac, admin_id, user_id, task1_id, task2_id = client
        user_token = await get_auth_token(ac, "user1", "userpass1234")

        # User1 trying to access admin's task
        response = await ac.get(
            f"/api/reports/{task1_id}/html",
            headers={"Authorization": f"Bearer {user_token}"}
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    async def test_get_html_report_without_auth(self, client):
        """Test that HTML report requires authentication."""
        ac, admin_id, user_id, task1_id, task2_id = client

        response = await ac.get(f"/api/reports/{task1_id}/html")

        assert response.status_code == 401

    async def test_get_html_report_path_traversal_rejected(self, client):
        """Test that path traversal attempts are rejected."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        # Try path traversal
        response = await ac.get(
            "/api/reports/../../../etc/passwd/html",
            headers={"Authorization": f"Bearer {token}"}
        )

        # Should reject with 400 (invalid UUID) or 404
        assert response.status_code in [400, 404]


class TestGetJSONReport:
    """Test GET /reports/{task_id}/json endpoint."""

    async def test_get_json_report_with_valid_token(self, client):
        """Test that owner can access their JSON report."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        response = await ac.get(
            f"/api/reports/{task1_id}/json",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]

    async def test_get_json_report_not_found(self, client):
        """Test accessing non-existent JSON report."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        response = await ac.get(
            "/api/reports/550e8400-e29b-41d4-a716-446655440999/json",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 404

    async def test_get_json_report_access_denied(self, client):
        """Test that user cannot access other user's JSON report."""
        ac, admin_id, user_id, task1_id, task2_id = client
        user_token = await get_auth_token(ac, "user1", "userpass1234")

        # User1 trying to access admin's task
        response = await ac.get(
            f"/api/reports/{task1_id}/json",
            headers={"Authorization": f"Bearer {user_token}"}
        )

        assert response.status_code == 403


class TestDeleteReport:
    """Test DELETE /reports/{task_id} endpoint."""

    async def test_delete_report_success(self, client):
        """Test that owner can delete their reports."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        # Get CSRF token
        csrf_response = await ac.get(
            "/api/csrf/token",
            headers={"Authorization": f"Bearer {token}"}
        )
        csrf_token = csrf_response.json()["csrf_token"]

        response = await ac.delete(
            f"/api/reports/{task1_id}",
            headers={
                "Authorization": f"Bearer {token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == task1_id
        assert "deleted_files" in data

        # Verify reports are deleted (should return 404 now)
        html_response = await ac.get(
            f"/api/reports/{task1_id}/html",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert html_response.status_code == 404

    async def test_delete_report_without_csrf_token(self, client):
        """Test that delete requires CSRF token."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        response = await ac.delete(
            f"/api/reports/{task1_id}",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403  # CSRF validation fails

    async def test_delete_report_access_denied(self, client):
        """Test that user cannot delete other user's reports."""
        ac, admin_id, user_id, task1_id, task2_id = client
        user_token = await get_auth_token(ac, "user1", "userpass1234")

        # Get CSRF token
        csrf_response = await ac.get(
            "/api/csrf/token",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        csrf_token = csrf_response.json()["csrf_token"]

        # User1 trying to delete admin's task
        response = await ac.delete(
            f"/api/reports/{task1_id}",
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    async def test_delete_nonexistent_report(self, client):
        """Test deleting non-existent report."""
        ac, admin_id, user_id, task1_id, task2_id = client
        token = await get_auth_token(ac, "admin", "Correct-Horse-Battery-Staple-2025!")

        csrf_response = await ac.get(
            "/api/csrf/token",
            headers={"Authorization": f"Bearer {token}"}
        )
        csrf_token = csrf_response.json()["csrf_token"]

        response = await ac.delete(
            "/api/reports/550e8400-e29b-41d4-a716-446655440999",
            headers={
                "Authorization": f"Bearer {token}",
                "X-CSRF-Token": csrf_token
            }
        )

        assert response.status_code == 404
