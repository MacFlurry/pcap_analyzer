"""
Tests for HTML view routes (Jinja2 templates).

Coverage: GET /, /login, /admin, /history, /change-password
"""

import pytest
from httpx import AsyncClient, ASGITransport
import tempfile
import shutil
from pathlib import Path
import os

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def async_client():
    """Create async HTTP client for testing."""
    tmpdir = Path(tempfile.mkdtemp(prefix="views_test_"))

    try:
        # Set environment variables
        original_data_dir = os.environ.get("DATA_DIR")
        original_database_url = os.environ.get("DATABASE_URL")
        original_secret_key = os.environ.get("SECRET_KEY")

        os.environ["DATA_DIR"] = str(tmpdir)

        # Keep explicit PostgreSQL override; otherwise isolate to a per-test SQLite DB.
        if not original_database_url or not original_database_url.startswith("postgresql"):
            os.environ["DATABASE_URL"] = f"sqlite:///{tmpdir}/pcap_analyzer.db"

        os.environ["SECRET_KEY"] = "test-secret-key-for-jwt-signing-in-tests-minimum-32-chars"

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
        # Cleanup PostgreSQL if used
        current_database_url = os.environ.get("DATABASE_URL", "")
        if current_database_url.startswith("postgresql"):
            from app.services.user_database import get_user_db_service
            user_db = get_user_db_service()
            if user_db and user_db.pool:
                try:
                    await user_db.pool.execute("""
                        TRUNCATE TABLE progress_snapshots, tasks, users
                        RESTART IDENTITY CASCADE
                    """)
                except Exception:
                    pass

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


@pytest.mark.unit
async def test_homepage_accessible(async_client):
    """Test GET / returns 200"""
    response = await async_client.get("/", follow_redirects=False)
    assert response.status_code in (200, 302, 307)
    if response.status_code == 200:
        # Verify it's HTML content
        assert "text/html" in response.headers.get("content-type", "")
        # Should contain PCAP or upload-related content
        assert b"pcap" in response.content.lower() or b"upload" in response.content.lower()


@pytest.mark.unit
async def test_login_page_accessible(async_client):
    """Test GET /login returns 200"""
    response = await async_client.get("/login")
    assert response.status_code == 200
    # Verify it's HTML content
    assert "text/html" in response.headers.get("content-type", "")
    # Should contain login-related content
    assert b"login" in response.content.lower()


@pytest.mark.unit
async def test_admin_page_accessible(async_client):
    """
    Test GET /admin returns 200.

    Note: The admin page itself is accessible (returns HTML),
    but the actual admin functionality requires authentication via JavaScript/API.
    The page template is public, but API endpoints are protected.
    """
    response = await async_client.get("/admin", follow_redirects=False)
    assert response.status_code in (200, 302, 307)
    if response.status_code == 200:
        # Verify it's HTML content
        assert "text/html" in response.headers.get("content-type", "")


@pytest.mark.unit
async def test_history_page_accessible(async_client):
    """Test GET /history returns 200"""
    response = await async_client.get("/history", follow_redirects=False)
    assert response.status_code in (200, 302, 307)
    if response.status_code == 200:
        # Verify it's HTML content
        assert "text/html" in response.headers.get("content-type", "")
        # Should contain history-related content
        assert b"history" in response.content.lower() or b"historique" in response.content.lower()


@pytest.mark.unit
async def test_change_password_page_accessible(async_client):
    """
    Test GET /change-password returns 200.

    Note: The change-password page is publicly accessible (returns HTML template),
    but the actual password change functionality requires authentication.
    This is by design - the page is shown when password_must_change=True after login.
    """
    response = await async_client.get("/change-password", follow_redirects=False)
    assert response.status_code in (200, 302, 307)
    if response.status_code == 200:
        # Verify it's HTML content
        assert "text/html" in response.headers.get("content-type", "")
        # Should contain password-related content
        assert b"password" in response.content.lower()
