"""
Integration tests for legacy data handling.

Tests that verify multi-tenant system correctly handles tasks with NULL owner_id
(legacy data from before multi-tenant feature was implemented).
"""

import pytest
from httpx import AsyncClient, ASGITransport
import tempfile
import shutil
from pathlib import Path
import os

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def async_client_postgres():
    """
    Create async HTTP client configured for PostgreSQL testing.

    Note: These tests are specifically for PostgreSQL as they test NULL owner_id behavior,
    which is a database-level concern relevant to multi-tenant isolation.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="legacy_test_"))

    try:
        # Set environment variables
        original_data_dir = os.environ.get("DATA_DIR")
        original_database_url = os.environ.get("DATABASE_URL")
        original_secret_key = os.environ.get("SECRET_KEY")

        os.environ["DATA_DIR"] = str(tmpdir)

        # Use PostgreSQL for these tests (fall back to SQLite if not available)
        if not original_database_url:
            # Skip these tests if PostgreSQL is not configured
            pytest.skip("PostgreSQL not configured (DATABASE_URL not set)")

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
        from app.models.user import UserCreate, UserRole

        db_service = get_db_service()
        await db_service.init_db()

        user_db_service = get_user_db_service()
        await user_db_service.init_db()
        await user_db_service.migrate_tasks_table()

        # Create test users
        admin_user = UserCreate(username="admin", email="admin@example.com", password="testpass1234")
        await user_db_service.create_user(admin_user, role=UserRole.ADMIN, auto_approve=True)

        regular_user = UserCreate(username="user1", email="user1@example.com", password="testpass1234")
        await user_db_service.create_user(regular_user, role=UserRole.USER, auto_approve=True)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
    finally:
        # Cleanup PostgreSQL
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


async def get_auth_token(client: AsyncClient, username: str, password: str) -> str:
    """Helper to get authentication token."""
    response = await client.post("/api/token", data={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.integration
async def test_regular_user_cannot_access_legacy_tasks(async_client_postgres):
    """Test regular user cannot access tasks with NULL owner_id (403)"""
    from app.services.database import get_db_service

    db = get_db_service()

    # Create a legacy task with NULL owner_id (simulating pre-multi-tenant data)
    # Direct database insert to bypass owner_id requirement
    query, params = db.pool.translate_query(
        """
        INSERT INTO tasks (task_id, filename, file_size_bytes, status, owner_id)
        VALUES (?, ?, ?, ?, NULL)
        """,
        ("legacy-task-001", "legacy.pcap", 1024, "completed")
    )
    await db.pool.execute(query, *params)

    # Regular user tries to access legacy task
    user_token = await get_auth_token(async_client_postgres, "user1", "testpass1234")
    response = await async_client_postgres.get(
        "/api/status/legacy-task-001",
        headers={"Authorization": f"Bearer {user_token}"}
    )

    # Should be forbidden - regular users cannot access tasks without owner
    assert response.status_code == 403


@pytest.mark.integration
async def test_admin_can_access_legacy_tasks(async_client_postgres):
    """Test admin can access tasks with NULL owner_id"""
    from app.services.database import get_db_service

    db = get_db_service()

    # Create a legacy task with NULL owner_id
    query, params = db.pool.translate_query(
        """
        INSERT INTO tasks (task_id, filename, file_size_bytes, status, owner_id)
        VALUES (?, ?, ?, ?, NULL)
        """,
        ("legacy-task-002", "legacy2.pcap", 2048, "completed")
    )
    await db.pool.execute(query, *params)

    # Admin accesses legacy task
    admin_token = await get_auth_token(async_client_postgres, "admin", "testpass1234")
    response = await async_client_postgres.get(
        "/api/status/legacy-task-002",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Admin should be able to access legacy tasks
    assert response.status_code == 200
    data = response.json()
    assert data["task_id"] == "legacy-task-002"


@pytest.mark.integration
async def test_legacy_task_in_admin_history(async_client_postgres):
    """Test admin history includes legacy tasks (NULL owner_id)"""
    from app.services.database import get_db_service
    from app.services.user_database import get_user_db_service

    db = get_db_service()
    user_db = get_user_db_service()

    # Get user ID for user1
    user1_obj = await user_db.get_user_by_username("user1")

    # Create 1 task with owner_id (belongs to user1)
    await db.create_task(
        task_id="owned-task-001",
        filename="owned.pcap",
        file_size_bytes=512,
        owner_id=user1_obj.id
    )

    # Create 1 legacy task with NULL owner_id
    query, params = db.pool.translate_query(
        """
        INSERT INTO tasks (task_id, filename, file_size_bytes, status, owner_id)
        VALUES (?, ?, ?, ?, NULL)
        """,
        ("legacy-task-003", "legacy3.pcap", 1024, "completed")
    )
    await db.pool.execute(query, *params)

    # Admin gets history
    admin_token = await get_auth_token(async_client_postgres, "admin", "testpass1234")
    response = await async_client_postgres.get(
        "/api/history",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == 200
    data = response.json()

    # Admin should see both tasks (owned + legacy)
    task_ids = [task["task_id"] for task in data["tasks"]]
    assert len(task_ids) == 2
    assert "owned-task-001" in task_ids
    assert "legacy-task-003" in task_ids
