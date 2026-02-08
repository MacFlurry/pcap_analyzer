"""
Tests for CSRF token endpoints.

Coverage: GET /api/csrf/token, POST /api/csrf/refresh
"""

import pytest
from httpx import AsyncClient, ASGITransport
import tempfile
import shutil
from pathlib import Path
import os

pytestmark = pytest.mark.asyncio


def _is_async_postgres_url(url: str | None) -> bool:
    """Return True only for asyncpg-compatible PostgreSQL URLs."""
    if not url:
        return False
    if url.startswith("postgresql+"):
        return False
    return url.startswith("postgresql://") or url.startswith("postgres://")


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    tmpdir = Path(tempfile.mkdtemp(prefix="csrf_test_"))

    try:
        # Set environment variables to temp directory
        original_data_dir = os.environ.get("DATA_DIR")
        original_database_url = os.environ.get("DATABASE_URL")
        original_secret_key = os.environ.get("SECRET_KEY")
        original_csrf_secret = os.environ.get("CSRF_SECRET_KEY")

        os.environ["DATA_DIR"] = str(tmpdir)

        # Keep explicit PostgreSQL override; otherwise isolate to a per-test SQLite DB.
        if not _is_async_postgres_url(original_database_url):
            os.environ["DATABASE_URL"] = f"sqlite:///{tmpdir}/pcap_analyzer.db"

        os.environ["SECRET_KEY"] = "test-secret-key-for-jwt-signing-in-tests-minimum-32-chars"
        os.environ["CSRF_SECRET_KEY"] = "test-csrf-secret-key-for-csrf-protection-minimum-32-chars"

        # Clear singletons
        import app.services.database
        import app.services.user_database
        app.services.database._db_service = None
        app.services.user_database._user_db_service = None

        # Import app and initialize databases
        from app.main import app
        from app.services.database import get_db_service
        from app.services.user_database import get_user_db_service
        from app.models.user import UserCreate, UserRole

        db_service = get_db_service()
        await db_service.init_db()

        user_db_service = get_user_db_service()
        await user_db_service.init_db()
        await user_db_service.migrate_tasks_table()

        # Create test admin user
        admin_user = UserCreate(
            username="admin",
            email="admin@example.com",
            password="admin_password"
        )
        await user_db_service.create_user(admin_user, role=UserRole.ADMIN, auto_approve=True)

        # Create test regular user
        regular_user = UserCreate(
            username="regular_user",
            email="user@example.com",
            password="Correct-Horse-Battery-Staple-2025!"
        )
        await user_db_service.create_user(regular_user, role=UserRole.USER, auto_approve=True)

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
        if original_csrf_secret:
            os.environ["CSRF_SECRET_KEY"] = original_csrf_secret
        elif "CSRF_SECRET_KEY" in os.environ:
            del os.environ["CSRF_SECRET_KEY"]

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


@pytest.mark.unit
async def test_get_csrf_token_authenticated(client):
    """Test CSRF token retrieval for authenticated user"""
    # Login as admin
    token = await get_auth_token(client, "admin", "admin_password")

    # Get CSRF token
    response = await client.get(
        "/api/csrf/token",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert "csrf_token" in data
    assert "header_name" in data
    assert "cookie_name" in data
    assert "expires_in" in data
    assert len(data["csrf_token"]) > 0


@pytest.mark.unit
async def test_get_csrf_token_unauthenticated(client):
    """Test CSRF token without authentication returns 401"""
    response = await client.get("/api/csrf/token")
    assert response.status_code == 401


@pytest.mark.unit
async def test_refresh_csrf_token(client):
    """Test CSRF token refresh works"""
    token = await get_auth_token(client, "admin", "admin_password")

    # Get initial CSRF token
    response1 = await client.get(
        "/api/csrf/token",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response1.status_code == 200
    csrf_token1 = response1.json()["csrf_token"]

    # Refresh CSRF token
    response2 = await client.post(
        "/api/csrf/refresh",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response2.status_code == 200
    data = response2.json()
    assert "csrf_token" in data
    assert "header_name" in data
    assert "cookie_name" in data
    assert "expires_in" in data
    # New token should be different from the old one (token rotation)
    csrf_token2 = data["csrf_token"]
    assert csrf_token2 != csrf_token1


@pytest.mark.unit
async def test_refresh_csrf_token_unauthenticated(client):
    """Test CSRF token refresh with invalid token"""
    response = await client.post(
        "/api/csrf/refresh",
        headers={"Authorization": "Bearer invalid_token"}
    )

    assert response.status_code == 401
