"""
Integration tests for Authentication API endpoints (Fully Async).
"""

import pytest
import uuid
import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.user import UserRole, UserCreate
from app.services.user_database import UserDatabaseService
from tests.integration.postgres_conftest import postgres_container, postgres_db_url, apply_migrations

@pytest.fixture
async def user_db(postgres_db_url, apply_migrations):
    """
    Fixture to provide a UserDatabaseService connected to the test container.
    """
    service = UserDatabaseService(database_url=postgres_db_url)
    await service.init_db()
    return service

@pytest.fixture
async def api_client(postgres_db_url, apply_migrations, test_data_dir, monkeypatch):
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
    
    # Patch DATA_DIR
    from app.api.routes import health, reports, upload
    monkeypatch.setattr(upload, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(upload, "UPLOADS_DIR", test_data_dir / "uploads")
    monkeypatch.setattr(reports, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(reports, "REPORTS_DIR", test_data_dir / "reports")
    monkeypatch.setattr(health, "DATA_DIR", test_data_dir)
    
    # Explicitly initialize pools to be safe
    from app.services.database import get_db_service
    from app.services.user_database import get_user_db_service
    
    db = get_db_service()
    await db.init_db()
    
    udb = get_user_db_service()
    await udb.init_db()
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    
    # Cleanup
    if udb.pool.pool:
        await udb.pool.close()
    if db.pool.pool:
        await db.pool.close()

@pytest.mark.integration
@pytest.mark.asyncio
class TestAuthAPI:
    """
    Tests for Authentication API endpoints.
    """
    async def test_user_registration_success(self, api_client):
        """Test successful user registration."""
        username = f"newuser_{uuid.uuid4()}"
        email = f"{username}@example.com"
        password = "SecurePassword123!"
        
        response = await api_client.post(
            "/api/register",
            json={
                "username": username,
                "email": email,
                "password": password
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == username
        assert data["email"] == email
        assert "id" in data
        assert data["is_approved"] is False

    async def test_user_registration_duplicate_username(self, api_client):
        """Test registration with existing username."""
        username = f"user_{uuid.uuid4()}"
        # 1. Register first user
        await api_client.post(
            "/api/register",
            json={
                "username": username,
                "email": f"email1_{uuid.uuid4()}@example.com",
                "password": "SecurePassword123!"
            }
        )
        
        # 2. Try to register with same username
        response = await api_client.post(
            "/api/register",
            json={
                "username": username,
                "email": f"email2_{uuid.uuid4()}@example.com",
                "password": "AnotherSecurePassword123!"
            }
        )
        
        assert response.status_code == 400
        assert "Username already exists" in response.json()["detail"]

    async def test_user_registration_duplicate_email(self, api_client):
        """Test registration with existing email."""
        email = f"email_{uuid.uuid4()}@example.com"
        # 1. Register first user
        await api_client.post(
            "/api/register",
            json={
                "username": f"user1_{uuid.uuid4()}",
                "email": email,
                "password": "SecurePassword123!"
            }
        )
        
        # 2. Try to register with same email
        response = await api_client.post(
            "/api/register",
            json={
                "username": f"user2_{uuid.uuid4()}",
                "email": email,
                "password": "AnotherSecurePassword123!"
            }
        )
        
        assert response.status_code == 400
        assert "Email already exists" in response.json()["detail"]

    async def test_user_registration_weak_password(self, api_client):
        """Test registration with weak password (zxcvbn check)."""
        response = await api_client.post(
            "/api/register",
            json={
                "username": "weakuser",
                "email": "weak@example.com",
                "password": "password123"
            }
        )
        
        assert response.status_code == 422

    async def test_login_flow(self, api_client, user_db):
        """Test full login flow including approval requirement."""
        username = f"loginuser_{uuid.uuid4()}"
        password = "SecurePassword123!"
        email = f"{username}@example.com"
        
        # 1. Register
        await api_client.post(
            "/api/register",
            json={
                "username": username,
                "email": email,
                "password": password
            }
        )
        
        # 2. Try to login (not approved yet)
        response = await api_client.post(
            "/api/token",
            data={
                "username": username,
                "password": password
            }
        )
        assert response.status_code == 403
        assert "Account pending approval" in response.json()["detail"]
        
        # 3. Approve user via direct DB access
        u = await user_db.get_user_by_username(username)
        # Create an admin user first to be the approver
        admin_id = str(uuid.uuid4())
        await user_db.pool.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, is_approved, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())",
            admin_id, f"admin_{uuid.uuid4()}", f"admin_{uuid.uuid4()}@test.com", "hash", "admin", True
        )
        await user_db.approve_user(u.id, admin_id)
        
        # 4. Login successfully
        response = await api_client.post(
            "/api/token",
            data={
                "username": username,
                "password": password
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        
        # 5. Login with wrong password
        response = await api_client.post(
            "/api/token",
            data={
                "username": username,
                "password": "WrongPassword123!"
            }
        )
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    async def test_token_validity_and_expiration(self, api_client, user_db):
        """Test token validity and expiration behavior."""
        from datetime import timedelta
        from app.auth import create_access_token
        
        username = f"tokenuser_{uuid.uuid4()}"
        password = "SecurePassword123!"
        user = await user_db.create_user(
            UserCreate(username=username, email=f"{username}@example.com", password=password),
            auto_approve=True
        )
        
        # 1. Test with valid token
        valid_token = create_access_token(user, expires_delta=timedelta(minutes=5))
        response = await api_client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {valid_token}"}
        )
        assert response.status_code == 200
        assert response.json()["username"] == username
        
        # 2. Test with expired token
        expired_token = create_access_token(user, expires_delta=timedelta(minutes=-5))
        response = await api_client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401
        assert "Could not validate credentials" in response.json()["detail"]

        # 3. Test with malformed token
        response = await api_client.get(
            "/api/users/me",
            headers={"Authorization": "Bearer not-a-real-token"}
        )
        assert response.status_code == 401

    async def test_password_policy_enforcement(self, api_client, user_db):
        """Test password update policies (strength and history)."""
        username = f"policyuser_{uuid.uuid4()}"
        password_v1 = "InitialPassword123!"
        password_v2 = "SecondValidPassword123!"
        
        user = await user_db.create_user(
            UserCreate(username=username, email=f"{username}@example.com", password=password_v1),
            auto_approve=True
        )
        from app.auth import create_access_token
        token = create_access_token(user)
        headers = {"Authorization": f"Bearer {token}"}
        
        # 1. Update with weak password
        response = await api_client.put(
            "/api/users/me",
            headers=headers,
            json={
                "current_password": password_v1,
                "new_password": "weak"
            }
        )
        assert response.status_code == 422
        
        # 2. Update with valid password
        response = await api_client.put(
            "/api/users/me",
            headers=headers,
            json={
                "current_password": password_v1,
                "new_password": password_v2
            }
        )
        assert response.status_code == 200
        
        # 3. Update with old password (history reuse prevention)
        response = await api_client.put(
            "/api/users/me",
            headers=headers,
            json={
                "current_password": password_v2,
                "new_password": password_v1
            }
        )
        assert response.status_code == 400
        assert "used recently" in response.json()["detail"]

    async def test_temporary_password_flow(self, api_client, user_db):
        """Test temporary password flow (admin creation -> force change)."""
        # 1. Admin creates a user
        admin_username = f"admin_{uuid.uuid4()}"
        admin_password = "AdminPassword123!"
        admin = await user_db.create_user(
            UserCreate(username=admin_username, email=f"{admin_username}@test.com", password=admin_password),
            role=UserRole.ADMIN,
            auto_approve=True
        )
        
        from app.auth import create_access_token
        admin_token = create_access_token(admin)
        
        new_username = f"tempuser_{uuid.uuid4()}"
        new_email = f"{new_username}@example.com"
        
        response = await api_client.post(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "username": new_username,
                "email": new_email,
                "role": "user"
            }
        )
        assert response.status_code == 201
        data = response.json()
        temp_password = data["temporary_password"]
        assert data["user"]["password_must_change"] is True
        
        # 2. Login with temporary password
        response = await api_client.post(
            "/api/token",
            data={
                "username": new_username,
                "password": temp_password
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["password_must_change"] is True
        temp_user_token = data["access_token"]
        
        # 3. Change password
        new_password = "NewSecurePassword123!"
        response = await api_client.put(
            "/api/users/me",
            headers={"Authorization": f"Bearer {temp_user_token}"},
            json={
                "current_password": temp_password,
                "new_password": new_password
            }
        )
        assert response.status_code == 200
        assert response.json()["password_must_change"] is False
        
        # 4. Verify new password works and doesn't require change
        response = await api_client.post(
            "/api/token",
            data={
                "username": new_username,
                "password": new_password
            }
        )
        assert response.status_code == 200
        assert response.json()["password_must_change"] is False