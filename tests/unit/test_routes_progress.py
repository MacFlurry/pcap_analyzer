"""
Tests unitaires pour les routes de progression

Includes multi-tenant isolation tests to verify users can only access their own tasks.
"""

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport
import tempfile
import shutil
from pathlib import Path
import os

pytestmark = pytest.mark.asyncio


@pytest.mark.unit
def test_get_progress_nonexistent_task(client: TestClient):
    """Test getting progress for non-existent task"""
    response = client.get("/api/progress/nonexistent-task")

    # Should return 404 or start SSE stream with error
    assert response.status_code in [200, 404]


@pytest.mark.unit
def test_get_task_status_nonexistent(client: TestClient):
    """Test getting status for non-existent task"""
    response = client.get("/api/status/nonexistent-task")

    assert response.status_code == 404


@pytest.mark.unit
def test_get_history_empty(client: TestClient):
    """Test getting history when no tasks exist"""
    response = client.get("/api/history")

    assert response.status_code == 200
    data = response.json()

    assert "tasks" in data
    assert "count" in data
    assert isinstance(data["tasks"], list)


@pytest.mark.unit
def test_get_history_with_limit(client: TestClient):
    """Test getting history with limit parameter"""
    response = client.get("/api/history?limit=10")

    assert response.status_code == 200
    data = response.json()

    assert len(data["tasks"]) <= 10


# =============================================================================
# Multi-Tenant Isolation Tests
# =============================================================================


@pytest.fixture
async def async_client():
    """Create async HTTP client for multi-tenant testing."""
    tmpdir = Path(tempfile.mkdtemp(prefix="multitenant_test_"))

    try:
        # Set environment variables
        original_data_dir = os.environ.get("DATA_DIR")
        original_database_url = os.environ.get("DATABASE_URL")
        original_secret_key = os.environ.get("SECRET_KEY")

        os.environ["DATA_DIR"] = str(tmpdir)

        # Support DATABASE_URL override for PostgreSQL testing
        if not original_database_url:
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
        from app.models.user import UserCreate, UserRole

        db_service = get_db_service()
        await db_service.init_db()

        user_db_service = get_user_db_service()
        await user_db_service.init_db()
        await user_db_service.migrate_tasks_table()

        # Create test users
        admin_user = UserCreate(username="admin", email="admin@example.com", password="testpass1234")
        await user_db_service.create_user(admin_user, role=UserRole.ADMIN, auto_approve=True)

        user_a = UserCreate(username="userA", email="userA@example.com", password="testpass1234")
        await user_db_service.create_user(user_a, role=UserRole.USER, auto_approve=True)

        user_b = UserCreate(username="userB", email="userB@example.com", password="testpass1234")
        await user_db_service.create_user(user_b, role=UserRole.USER, auto_approve=True)

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


async def get_auth_token(client: AsyncClient, username: str, password: str) -> str:
    """Helper to get authentication token."""
    response = await client.post("/api/token", data={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.unit
async def test_user_cannot_view_other_task_status(async_client):
    """Test user cannot view another user's task status (403)"""
    from app.services.database import get_db_service
    from app.services.user_database import get_user_db_service

    db = get_db_service()
    user_db = get_user_db_service()

    # Get user IDs
    user_a_obj = await user_db.get_user_by_username("userA")
    user_b_obj = await user_db.get_user_by_username("userB")

    # User A creates a task
    task_a = await db.create_task(
        task_id="task-userA-001",
        filename="userA.pcap",
        file_size_bytes=1024,
        owner_id=user_a_obj.id
    )

    # User B tries to access User A's task status
    token_b = await get_auth_token(async_client, "userB", "testpass1234")
    response = await async_client.get(
        f"/api/status/{task_a.task_id}",
        headers={"Authorization": f"Bearer {token_b}"}
    )

    # Should be forbidden (403) - user B cannot see user A's task
    assert response.status_code == 403


@pytest.mark.unit
async def test_admin_can_view_all_task_status(async_client):
    """Test admin can view all users' task status"""
    from app.services.database import get_db_service
    from app.services.user_database import get_user_db_service

    db = get_db_service()
    user_db = get_user_db_service()

    # Get user ID
    user_a_obj = await user_db.get_user_by_username("userA")

    # User A creates a task
    task_a = await db.create_task(
        task_id="task-userA-002",
        filename="userA2.pcap",
        file_size_bytes=1024,
        owner_id=user_a_obj.id
    )

    # Admin accesses User A's task status
    admin_token = await get_auth_token(async_client, "admin", "testpass1234")
    response = await async_client.get(
        f"/api/status/{task_a.task_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Should be OK (200) - admin can see all tasks
    assert response.status_code == 200


@pytest.mark.unit
async def test_history_filtered_by_owner(async_client):
    """Test regular user sees only their own history"""
    from app.services.database import get_db_service
    from app.services.user_database import get_user_db_service

    db = get_db_service()
    user_db = get_user_db_service()

    # Get user IDs
    user_a_obj = await user_db.get_user_by_username("userA")
    user_b_obj = await user_db.get_user_by_username("userB")

    # User A creates 2 tasks
    await db.create_task(task_id="task-A-1", filename="a1.pcap", file_size_bytes=100, owner_id=user_a_obj.id)
    await db.create_task(task_id="task-A-2", filename="a2.pcap", file_size_bytes=100, owner_id=user_a_obj.id)

    # User B creates 1 task
    await db.create_task(task_id="task-B-1", filename="b1.pcap", file_size_bytes=100, owner_id=user_b_obj.id)

    # User A gets history
    token_a = await get_auth_token(async_client, "userA", "testpass1234")
    response_a = await async_client.get(
        "/api/history",
        headers={"Authorization": f"Bearer {token_a}"}
    )

    assert response_a.status_code == 200
    data_a = response_a.json()

    # User A should only see their own 2 tasks
    task_ids_a = [task["task_id"] for task in data_a["tasks"]]
    assert len(task_ids_a) == 2
    assert "task-A-1" in task_ids_a
    assert "task-A-2" in task_ids_a
    assert "task-B-1" not in task_ids_a


@pytest.mark.unit
async def test_history_admin_sees_all(async_client):
    """Test admin sees all users' history"""
    from app.services.database import get_db_service
    from app.services.user_database import get_user_db_service

    db = get_db_service()
    user_db = get_user_db_service()

    # Get user IDs
    user_a_obj = await user_db.get_user_by_username("userA")
    user_b_obj = await user_db.get_user_by_username("userB")

    # User A creates 2 tasks
    await db.create_task(task_id="task-admin-A-1", filename="a1.pcap", file_size_bytes=100, owner_id=user_a_obj.id)
    await db.create_task(task_id="task-admin-A-2", filename="a2.pcap", file_size_bytes=100, owner_id=user_a_obj.id)

    # User B creates 1 task
    await db.create_task(task_id="task-admin-B-1", filename="b1.pcap", file_size_bytes=100, owner_id=user_b_obj.id)

    # Admin gets history
    admin_token = await get_auth_token(async_client, "admin", "testpass1234")
    response_admin = await async_client.get(
        "/api/history",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response_admin.status_code == 200
    data_admin = response_admin.json()

    # Admin should see all 3 tasks
    task_ids = [task["task_id"] for task in data_admin["tasks"]]
    assert len(task_ids) == 3
    assert "task-admin-A-1" in task_ids
    assert "task-admin-A-2" in task_ids
    assert "task-admin-B-1" in task_ids
