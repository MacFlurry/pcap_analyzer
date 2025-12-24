"""
Integration tests for Authentication and Admin User Management API endpoints.
"""

import pytest
import uuid
from app.models.user import UserCreate, UserRole, UserResponse

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

@pytest.mark.integration
@pytest.mark.asyncio
class TestAdminAPI:
    """
    Tests for Admin-only User Management API endpoints.
    """
    @pytest.fixture
    async def admin_headers(self, user_db):
        from app.auth import create_access_token
        admin = await user_db.create_user(
            UserCreate(username=f"admin_{uuid.uuid4().hex[:4]}", email=f"admin_{uuid.uuid4().hex[:4]}@test.com", password="AdminPassword123!"),
            role=UserRole.ADMIN,
            auto_approve=True
        )
        token = create_access_token(admin)
        return {"Authorization": f"Bearer {token}"}, admin

    async def test_get_all_users(self, api_client, admin_headers):
        headers, _ = admin_headers
        response = await api_client.get("/api/users", headers=headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        assert len(response.json()) >= 1

    async def test_admin_approve_block_unblock_flow(self, api_client, admin_headers, user_db):
        headers, admin = admin_headers
        
        # 1. Create a user needing approval
        user_name = f"flowuser_{uuid.uuid4().hex[:4]}"
        user = await user_db.create_user(
            UserCreate(username=user_name, email=f"{user_name}@test.com", password="SecurePassword123!"),
            auto_approve=False
        )
        assert user.is_approved is False
        
        # 2. Approve user
        response = await api_client.put(f"/api/admin/users/{user.id}/approve", headers=headers)
        assert response.status_code == 200
        assert response.json()["is_approved"] is True
        
        # 3. Block user
        response = await api_client.put(f"/api/admin/users/{user.id}/block", headers=headers)
        assert response.status_code == 200
        assert response.json()["is_active"] is False
        
        # 4. Unblock user
        response = await api_client.put(f"/api/admin/users/{user.id}/unblock", headers=headers)
        assert response.status_code == 200
        assert response.json()["is_active"] is True

    async def test_bulk_actions(self, api_client, admin_headers, user_db):
        headers, _ = admin_headers
        
        # Create 2 users
        u1 = await user_db.create_user(
            UserCreate(username=f"u1_{uuid.uuid4().hex[:4]}", email=f"u1_{uuid.uuid4().hex[:4]}@test.com", password="SecurePassword123!"),
            auto_approve=False
        )
        u2 = await user_db.create_user(
            UserCreate(username=f"u2_{uuid.uuid4().hex[:4]}", email=f"u2_{uuid.uuid4().hex[:4]}@test.com", password="SecurePassword123!"),
            auto_approve=False
        )
        
        # Bulk Approve
        response = await api_client.post(
            "/api/admin/users/bulk/approve",
            headers=headers,
            json={"user_ids": [u1.id, u2.id]}
        )
        assert response.status_code == 200
        assert response.json()["success"] == 2
        
        # Bulk Block
        response = await api_client.post(
            "/api/admin/users/bulk/block",
            headers=headers,
            json={"user_ids": [u1.id, u2.id]}
        )
        assert response.status_code == 200
        assert response.json()["success"] == 2
        
        # Bulk Unblock
        response = await api_client.post(
            "/api/admin/users/bulk/unblock",
            headers=headers,
            json={"user_ids": [u1.id, u2.id]}
        )
        assert response.status_code == 200
        assert response.json()["success"] == 2

    async def test_delete_user(self, api_client, admin_headers, user_db):
        headers, _ = admin_headers
        user = await user_db.create_user(
            UserCreate(username=f"del_{uuid.uuid4().hex[:4]}", email=f"del_{uuid.uuid4().hex[:4]}@test.com", password="SecurePassword123!"),
            auto_approve=True
        )
        
        response = await api_client.delete(f"/api/admin/users/{user.id}", headers=headers)
        assert response.status_code == 200
        assert "deleted successfully" in response.json()["message"]
        
        # Verify gone
        check = await user_db.get_user_by_id(user.id)
        assert check is None