"""
Integration tests for user list pagination and filtering.
"""

import pytest
import uuid
from app.models.user import UserCreate, UserRole

@pytest.mark.integration
@pytest.mark.asyncio
class TestUsersPaginationAPI:
    """
    Tests for GET /api/users with pagination and filtering.
    """
    
    @pytest.fixture
    async def admin_headers(self, user_db, api_client):
        from app.auth import create_access_token
        admin = await user_db.create_user(
            UserCreate(username=f"admin_{uuid.uuid4().hex[:4]}", email=f"admin_{uuid.uuid4().hex[:4]}@test.com", password="SecurePassword123!"),
            role=UserRole.ADMIN,
            auto_approve=True
        )
        token = create_access_token(admin)
        return {"Authorization": f"Bearer {token}"}

    @pytest.fixture
    async def setup_users(self, user_db):
        """Create a controlled set of users for testing pagination and filtering."""
        # Use a unique suffix for this test run to avoid cross-test pollution
        suffix = uuid.uuid4().hex[:6]
        
        # 5 Approved & Active
        for i in range(5):
            await user_db.create_user(
                UserCreate(username=f"app_{i}_{suffix}", email=f"app_{i}_{suffix}@test.com", password="SecurePassword123!"),
                auto_approve=True
            )
        
        # 2 Pending (Approved=False, Active=True)
        for i in range(2):
            await user_db.create_user(
                UserCreate(username=f"pen_{i}_{suffix}", email=f"pen_{i}_{suffix}@test.com", password="SecurePassword123!"),
                auto_approve=False
            )
            
        # 3 Blocked (Active=False)
        for i in range(3):
            user = await user_db.create_user(
                UserCreate(username=f"blk_{i}_{suffix}", email=f"blk_{i}_{suffix}@test.com", password="SecurePassword123!"),
                auto_approve=True
            )
            await user_db.block_user(user.id)
            
        return suffix

    async def test_get_users_no_pagination_legacy(self, api_client, admin_headers, setup_users):
        """Test legacy behavior: returns List[UserResponse] when no offset provided."""
        response = await api_client.get("/api/users", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Filter by suffix to count only users from this setup
        suffix = setup_users
        current_users = [u for u in data if suffix in u["username"]]
        assert len(current_users) == 10

    async def test_get_users_with_pagination(self, api_client, admin_headers, setup_users):
        """Test paginated response when offset is provided."""
        suffix = setup_users
        response = await api_client.get("/api/users?limit=100&offset=0", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        
        assert "users" in data
        assert "total" in data
        
        current_users = [u for u in data["users"] if suffix in u["username"]]
        assert len(current_users) == 10

    async def test_get_users_filter_status(self, api_client, admin_headers, setup_users):
        """Test filtering by status."""
        suffix = setup_users
        
        # 1. Filter pending (expect 2)
        response = await api_client.get("/api/users?status=pending&offset=0", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        current_pending = [u for u in data["users"] if suffix in u["username"]]
        assert len(current_pending) == 2
        for u in current_pending:
            assert u["is_approved"] is False

        # 2. Filter blocked (expect 3)
        response = await api_client.get("/api/users?status=blocked&offset=0", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        current_blocked = [u for u in data["users"] if suffix in u["username"]]
        assert len(current_blocked) == 3
        for u in current_blocked:
            assert u["is_active"] is False

        # 3. Filter approved (expect 5)
        response = await api_client.get("/api/users?status=approved&offset=0", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        current_approved = [u for u in data["users"] if suffix in u["username"]]
        assert len(current_approved) == 5
        for u in current_approved:
            assert u["is_approved"] is True
            assert u["is_active"] is True

    async def test_get_users_filter_role(self, api_client, admin_headers, setup_users):
        """Test filtering by role."""
        suffix = setup_users
        response = await api_client.get("/api/users?role=user&offset=0&limit=100", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        current_role_users = [u for u in data["users"] if suffix in u["username"]]
        assert len(current_role_users) == 10
        for u in current_role_users:
            assert u["role"] == "user"