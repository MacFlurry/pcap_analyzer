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
async def async_client_postgres(postgres_db_url, apply_migrations, test_postgres_pool, tmp_path):
    """
    Create async HTTP client configured for PostgreSQL testing.
    """
    # Set environment variables
    os.environ["DATA_DIR"] = str(tmp_path)
    os.environ["DATABASE_URL"] = postgres_db_url
    os.environ["SECRET_KEY"] = "test-secret-key-for-jwt-signing-in-tests-minimum-32-chars"

    # Clear singletons
    from app.services import database as db_mod
    from app.services import user_database as udb_mod
    from app.services import postgres_database as pdb_mod
    db_mod._db_service = None
    udb_mod._user_db_service = None
    pdb_mod._db_pool = None

    # Import app and initialize databases
    from app.main import app
    from app.services.database import DatabaseService
    from app.services.user_database import UserDatabaseService
    from app.models.user import UserCreate, UserRole

    db_service = DatabaseService(database_url=postgres_db_url)
    db_service.pool = test_postgres_pool
    await db_service.init_db()
    db_mod._db_service = db_service

    user_db_service = UserDatabaseService(database_url=postgres_db_url)
    user_db_service.pool = test_postgres_pool
    await user_db_service.init_db()
    udb_mod._user_db_service = user_db_service
    await user_db_service.migrate_tasks_table()

    # Create test users
    try:
        admin_user = UserCreate(username="admin", email="admin@example.com", password="Correct-Horse-Battery-Staple-2025!")
        await user_db_service.create_user(admin_user, role=UserRole.ADMIN, auto_approve=True)
    except Exception:
        pass

    try:
        regular_user = UserCreate(username="user1", email="user1@example.com", password="Correct-Horse-Battery-Staple-2025!")
        await user_db_service.create_user(regular_user, role=UserRole.USER, auto_approve=True)
    except Exception:
        pass

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    
    # Cleanup
    app.dependency_overrides.clear()
    from tests.conftest import cleanup_database
    await cleanup_database(test_postgres_pool)


async def get_auth_token(client: AsyncClient, username: str, password: str) -> str:
    """Helper to get authentication token."""
    response = await client.post("/api/token", data={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.integration
async def test_regular_user_cannot_access_legacy_tasks(async_client_postgres):
    """Test regular user cannot access tasks with NULL owner_id (403)"""
    from app.services.database import get_db_service
    from datetime import datetime, timezone

    db = get_db_service()
    now = datetime.now(timezone.utc)

    # Create a legacy task with NULL owner_id (simulating pre-multi-tenant data)
    # Direct database insert to bypass owner_id requirement
    query, params = db.pool.translate_query(
        """
        INSERT INTO tasks (task_id, filename, file_size_bytes, status, owner_id, uploaded_at)
        VALUES (?, ?, ?, ?, NULL, ?)
        """,
        ("00000000-0000-0000-0000-000000000001", "legacy.pcap", 1024, "completed", now)
    )
    await db.pool.execute(query, *params)

    # Regular user tries to access legacy task
    user_token = await get_auth_token(async_client_postgres, "user1", "Correct-Horse-Battery-Staple-2025!")
    response = await async_client_postgres.get(
        "/api/status/00000000-0000-0000-0000-000000000001",
        headers={"Authorization": f"Bearer {user_token}"}
    )

    # Should be forbidden - regular users cannot access tasks without owner
    assert response.status_code == 403


@pytest.mark.integration
async def test_admin_can_access_legacy_tasks(async_client_postgres):
    """Test admin can access tasks with NULL owner_id"""
    from app.services.database import get_db_service
    from datetime import datetime, timezone

    db = get_db_service()
    now = datetime.now(timezone.utc)

    # Create a legacy task with NULL owner_id
    query, params = db.pool.translate_query(
        """
        INSERT INTO tasks (task_id, filename, file_size_bytes, status, owner_id, uploaded_at)
        VALUES (?, ?, ?, ?, NULL, ?)
        """,
        ("00000000-0000-0000-0000-000000000002", "legacy2.pcap", 2048, "completed", now)
    )
    await db.pool.execute(query, *params)

    # Admin accesses legacy task
    admin_token = await get_auth_token(async_client_postgres, "admin", "Correct-Horse-Battery-Staple-2025!")
    response = await async_client_postgres.get(
        "/api/status/00000000-0000-0000-0000-000000000002",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    # Admin should be able to access legacy tasks
    assert response.status_code == 200
    data = response.json()
    assert data["task_id"] == "00000000-0000-0000-0000-000000000002"


@pytest.mark.integration
async def test_legacy_task_in_admin_history(async_client_postgres):
    """Test admin history includes legacy tasks (NULL owner_id)"""
    from app.services.database import get_db_service
    from app.services.user_database import get_user_db_service
    from datetime import datetime, timezone

    db = get_db_service()
    user_db = get_user_db_service()
    now = datetime.now(timezone.utc)

    # Get user ID for user1
    user1_obj = await user_db.get_user_by_username("user1")

    # Create 1 task with owner_id (belongs to user1)
    await db.create_task(
        task_id="00000000-0000-0000-0000-000000000004",
        filename="owned.pcap",
        file_size_bytes=512,
        owner_id=user1_obj.id
    )

    # Create 1 legacy task with NULL owner_id
    query, params = db.pool.translate_query(
        """
        INSERT INTO tasks (task_id, filename, file_size_bytes, status, owner_id, uploaded_at)
        VALUES (?, ?, ?, ?, NULL, ?)
        """,
        ("00000000-0000-0000-0000-000000000003", "legacy3.pcap", 1024, "completed", now)
    )
    await db.pool.execute(query, *params)

    # Admin gets history
    admin_token = await get_auth_token(async_client_postgres, "admin", "Correct-Horse-Battery-Staple-2025!")
    response = await async_client_postgres.get(
        "/api/history",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    assert response.status_code == 200
    data = response.json()

    # Admin should see both tasks (owned + legacy)
    task_ids = [task["task_id"] for task in data["tasks"]]
    assert len(task_ids) == 2
    assert "00000000-0000-0000-0000-000000000004" in task_ids
    assert "00000000-0000-0000-0000-000000000003" in task_ids
