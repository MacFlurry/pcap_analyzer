"""
Shared fixtures for integration tests.
Includes PostgreSQL testcontainer and Alembic migrations.
"""

import pytest
import os
import uuid
import asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.models.user import UserCreate, UserRole
from app.services.user_database import UserDatabaseService
from app.services.database import DatabaseService
from app.auth import create_access_token

@pytest.fixture
async def user_db(postgres_db_url, apply_migrations, test_postgres_pool):
    """
    Fixture to provide a UserDatabaseService connected to the test container.
    """
    service = UserDatabaseService(database_url=postgres_db_url)
    service.pool = test_postgres_pool
    await service.init_db()
    return service

@pytest.fixture
async def task_db(postgres_db_url, apply_migrations, test_postgres_pool):
    """
    Fixture to provide a DatabaseService connected to the test container.
    """
    service = DatabaseService(database_url=postgres_db_url)
    service.pool = test_postgres_pool
    await service.init_db()
    return service

@pytest.fixture
async def api_client(postgres_db_url, apply_migrations, test_postgres_pool, test_data_dir, monkeypatch):
    """
    Async HTTP client for testing FastAPI endpoints.
    """
    monkeypatch.setenv("DATABASE_URL", postgres_db_url)
    monkeypatch.setenv("SECRET_KEY", "test_secret_key_must_be_32_chars_long_min")
    monkeypatch.setenv("DATA_DIR", str(test_data_dir))
    
    # Reset singletons
    from app.services import user_database, database, worker, analyzer, postgres_database
    user_database._user_db_service = None
    database._db_service = None
    worker._worker = None
    analyzer._analyzer_service = None
    postgres_database._db_pool = None
    
    # Patch DATA_DIR in routes modules
    from app.api.routes import health, reports, upload
    monkeypatch.setattr(upload, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(upload, "UPLOADS_DIR", test_data_dir / "uploads")
    monkeypatch.setattr(reports, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(reports, "REPORTS_DIR", test_data_dir / "reports")
    monkeypatch.setattr(health, "DATA_DIR", test_data_dir)
    
    # Explicitly initialize pools using shared pool
    db = database.get_db_service()
    db.pool = test_postgres_pool
    await db.init_db()
    
    udb = user_database.get_user_db_service()
    udb.pool = test_postgres_pool
    await udb.init_db()
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    
    # DO NOT Cleanup shared pool here
    app.dependency_overrides = {}

@pytest.fixture
async def auth_user(user_db):
    """
    Creates an approved test user and returns the user object.
    """
    username = f"testuser_{uuid.uuid4().hex[:8]}"
    user = await user_db.create_user(
        UserCreate(
            username=username,
            email=f"{username}@example.com",
            password="SecurePassword123!"
        ),
        auto_approve=True
    )
    return user

@pytest.fixture
def auth_headers(auth_user):
    """
    Returns headers with a valid Bearer token for the auth_user.
    """
    token = create_access_token(auth_user)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
async def csrf_token(api_client, auth_headers):
    """
    Gets a valid CSRF token for the authenticated user.
    """
    response = await api_client.get("/api/csrf/token", headers=auth_headers)
    assert response.status_code == 200
    return response.json()["csrf_token"]

@pytest.fixture
def auth_with_csrf(auth_headers, csrf_token):
    """
    Returns headers with both Bearer token and CSRF token.
    """
    headers = auth_headers.copy()
    headers["X-CSRF-Token"] = csrf_token
    return headers