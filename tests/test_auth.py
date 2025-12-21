"""
Tests for Authentication endpoints.

Coverage target: > 70%
"""

import pytest
from httpx import AsyncClient, ASGITransport
import tempfile
import shutil
from pathlib import Path
import os

from app.models.user import UserRole

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def client():
    """Create async HTTP client for testing (supports SQLite and PostgreSQL via DATABASE_URL)."""
    tmpdir = Path(tempfile.mkdtemp(prefix="auth_test_"))

    try:
        # Set environment variables to temp directory
        original_data_dir = os.environ.get("DATA_DIR")
        original_database_url = os.environ.get("DATABASE_URL")
        original_secret_key = os.environ.get("SECRET_KEY")

        os.environ["DATA_DIR"] = str(tmpdir)

        # Support DATABASE_URL override for PostgreSQL testing
        # Only set to SQLite if not already configured
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
        from app.models.user import UserCreate

        db_service = get_db_service()
        await db_service.init_db()

        user_db_service = get_user_db_service()
        await user_db_service.init_db()
        await user_db_service.migrate_tasks_table()

        # Create test admin user
        admin_user = UserCreate(
            username="admin",
            email="admin@example.com",
            password="testpass1234"
        )
        await user_db_service.create_user(admin_user, role=UserRole.ADMIN, auto_approve=True)

        # Create test regular user (approved)
        regular_user = UserCreate(
            username="user1",
            email="user1@example.com",
            password="userpass1234"
        )
        await user_db_service.create_user(regular_user, role=UserRole.USER, auto_approve=True)

        # Create test unapproved user
        unapproved_user = UserCreate(
            username="unapproved",
            email="unapproved@example.com",
            password="unapprovedpass1234"
        )
        await user_db_service.create_user(unapproved_user, role=UserRole.USER, auto_approve=False)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
    finally:
        # Cleanup PostgreSQL if used (TRUNCATE tables for isolation)
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
                    pass  # Tables might not exist

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


class TestLogin:
    """Test login endpoint."""

    async def test_login_with_valid_admin_credentials(self, client: AsyncClient):
        """Test successful login with admin credentials."""
        response = await client.post(
            "/api/token",
            data={"username": "admin", "password": "testpass1234"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert data["password_must_change"] == False

    async def test_login_with_valid_user_credentials(self, client: AsyncClient):
        """Test successful login with regular user credentials."""
        response = await client.post(
            "/api/token",
            data={"username": "user1", "password": "userpass1234"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_with_invalid_username(self, client: AsyncClient):
        """Test login with non-existent username."""
        response = await client.post(
            "/api/token",
            data={"username": "nonexistent", "password": "anypassword"}
        )

        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    async def test_login_with_invalid_password(self, client: AsyncClient):
        """Test login with wrong password."""
        response = await client.post(
            "/api/token",
            data={"username": "admin", "password": "wrongpassword"}
        )

        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    async def test_login_with_unapproved_account(self, client: AsyncClient):
        """Test that unapproved accounts cannot login."""
        response = await client.post(
            "/api/token",
            data={"username": "unapproved", "password": "unapprovedpass1234"}
        )

        assert response.status_code == 403
        assert "pending approval" in response.json()["detail"].lower()


class TestRegistration:
    """Test user registration endpoint."""

    async def test_register_new_user(self, client: AsyncClient):
        """Test successful user registration."""
        response = await client.post(
            "/api/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "newuserpass1234"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
        assert data["role"] == "user"
        assert data["is_active"] == True
        assert data["is_approved"] == False  # Not auto-approved

    async def test_register_duplicate_username(self, client: AsyncClient):
        """Test registration with existing username."""
        response = await client.post(
            "/api/register",
            json={
                "username": "admin",
                "email": "different@example.com",
                "password": "somepassword123"
            }
        )

        assert response.status_code == 400
        assert "already exists" in response.json()["detail"].lower()

    async def test_register_duplicate_email(self, client: AsyncClient):
        """Test registration with existing email."""
        response = await client.post(
            "/api/register",
            json={
                "username": "differentuser",
                "email": "admin@example.com",
                "password": "somepassword123"
            }
        )

        assert response.status_code == 400
        assert "already exists" in response.json()["detail"].lower()


class TestGetCurrentUser:
    """Test get current user info endpoint."""

    async def test_get_current_user_with_valid_token(self, client: AsyncClient):
        """Test getting current user info with valid token."""
        token = await get_auth_token(client, "admin", "testpass1234")

        response = await client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"
        assert "hashed_password" not in data  # Should not expose password

    async def test_get_current_user_without_token(self, client: AsyncClient):
        """Test that endpoint requires authentication."""
        response = await client.get("/api/users/me")

        assert response.status_code == 401


class TestUpdatePassword:
    """Test password update endpoint."""

    async def test_update_password_success(self, client: AsyncClient):
        """Test successful password update."""
        token = await get_auth_token(client, "user1", "userpass1234")

        response = await client.put(
            "/api/users/me",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "current_password": "userpass1234",
                "new_password": "newpassword1234"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "user1"

        # Verify new password works
        login_response = await client.post(
            "/api/token",
            data={"username": "user1", "password": "newpassword1234"}
        )
        assert login_response.status_code == 200

    async def test_update_password_wrong_current_password(self, client: AsyncClient):
        """Test password update with wrong current password."""
        token = await get_auth_token(client, "user1", "userpass1234")

        response = await client.put(
            "/api/users/me",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "current_password": "wrongpassword",
                "new_password": "newpassword1234"
            }
        )

        assert response.status_code == 401
        assert "Incorrect current password" in response.json()["detail"]

    async def test_update_password_too_short(self, client: AsyncClient):
        """Test password update with too short new password."""
        token = await get_auth_token(client, "user1", "userpass1234")

        response = await client.put(
            "/api/users/me",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "current_password": "userpass1234",
                "new_password": "short"
            }
        )

        # Pydantic validates min_length before endpoint handler
        assert response.status_code == 422  # Validation error
        data = response.json()
        assert "detail" in data


class TestAdminListUsers:
    """Test admin list users endpoint."""

    async def test_admin_list_users(self, client: AsyncClient):
        """Test that admin can list all users."""
        token = await get_auth_token(client, "admin", "testpass1234")

        response = await client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        users = response.json()
        assert isinstance(users, list)
        assert len(users) >= 3  # admin, user1, unapproved

        # Check user structure
        assert all("username" in user for user in users)
        assert all("hashed_password" not in user for user in users)

    async def test_admin_list_users_with_limit(self, client: AsyncClient):
        """Test listing users with limit parameter."""
        token = await get_auth_token(client, "admin", "testpass1234")

        response = await client.get(
            "/api/users?limit=1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        users = response.json()
        assert len(users) == 1

    async def test_non_admin_cannot_list_users(self, client: AsyncClient):
        """Test that regular users cannot list all users."""
        token = await get_auth_token(client, "user1", "userpass1234")

        response = await client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403


class TestAdminApproveUser:
    """Test admin approve user endpoint."""

    async def test_admin_approve_user(self, client: AsyncClient):
        """Test that admin can approve unapproved user."""
        token = await get_auth_token(client, "admin", "testpass1234")

        # Get unapproved user ID
        users_response = await client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        users = users_response.json()
        unapproved_user = next(u for u in users if u["username"] == "unapproved")
        user_id = unapproved_user["id"]

        # Approve user
        response = await client.put(
            f"/api/admin/users/{user_id}/approve",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_approved"] == True
        assert data["approved_by"] is not None

    async def test_approve_nonexistent_user(self, client: AsyncClient):
        """Test approving non-existent user returns 404."""
        token = await get_auth_token(client, "admin", "testpass1234")

        response = await client.put(
            "/api/admin/users/nonexistent-id/approve",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 404


class TestAdminBlockUser:
    """Test admin block user endpoint."""

    async def test_admin_block_user(self, client: AsyncClient):
        """Test that admin can block a user."""
        token = await get_auth_token(client, "admin", "testpass1234")

        # Get user1 ID
        users_response = await client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        users = users_response.json()
        user1 = next(u for u in users if u["username"] == "user1")
        user_id = user1["id"]

        # Block user
        response = await client.put(
            f"/api/admin/users/{user_id}/block",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] == False

        # Verify user cannot login
        login_response = await client.post(
            "/api/token",
            data={"username": "user1", "password": "userpass1234"}
        )
        assert login_response.status_code == 403

    async def test_admin_cannot_block_self(self, client: AsyncClient):
        """Test that admin cannot block their own account."""
        token = await get_auth_token(client, "admin", "testpass1234")

        # Get admin ID
        users_response = await client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"}
        )
        users = users_response.json()
        admin_user = next(u for u in users if u["username"] == "admin")
        admin_id = admin_user["id"]

        # Try to block self
        response = await client.put(
            f"/api/admin/users/{admin_id}/block",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 400
        assert "Cannot block your own account" in response.json()["detail"]

    async def test_block_nonexistent_user(self, client: AsyncClient):
        """Test blocking non-existent user returns 404."""
        token = await get_auth_token(client, "admin", "testpass1234")

        response = await client.put(
            "/api/admin/users/nonexistent-id/block",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 404


class TestAdminCreateUser:
    """Test admin create user endpoint."""

    async def test_admin_create_user_with_temporary_password(self, client: AsyncClient):
        """Test that admin can create user with temporary password."""
        token = await get_auth_token(client, "admin", "testpass1234")

        response = await client.post(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "username": "created_user",
                "email": "created@example.com",
                "role": "user"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert "temporary_password" in data
        assert data["user"]["username"] == "created_user"
        assert data["user"]["is_approved"] == True
        assert data["user"]["password_must_change"] == True

        # Verify user can login with temporary password
        temp_password = data["temporary_password"]
        login_response = await client.post(
            "/api/token",
            data={"username": "created_user", "password": temp_password}
        )
        assert login_response.status_code == 200
        assert login_response.json()["password_must_change"] == True


class TestAdminUnblockUser:
    """Test admin unblock user endpoint."""

    async def test_admin_unblock_user(self, client: AsyncClient):
        """Test that admin can unblock a blocked user."""
        token = await get_auth_token(client, "admin", "testpass1234")

        # First, create and block a user
        # Create a new user
        from app.services.user_database import get_user_db_service
        from app.models.user import UserCreate, UserRole
        user_db = get_user_db_service()
        new_user = UserCreate(
            username="blocktest",
            email="blocktest@example.com",
            password="testpass1234"
        )
        created_user = await user_db.create_user(new_user, role=UserRole.USER, auto_approve=True)

        # Block the user
        block_response = await client.put(
            f"/api/admin/users/{created_user.id}/block",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert block_response.status_code == 200
        assert block_response.json()["is_active"] == False

        # Now unblock the user
        unblock_response = await client.put(
            f"/api/admin/users/{created_user.id}/unblock",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert unblock_response.status_code == 200
        data = unblock_response.json()
        assert data["is_active"] == True
        assert data["username"] == "blocktest"

    async def test_admin_unblock_nonexistent_user(self, client: AsyncClient):
        """Test unblocking non-existent user returns 404."""
        token = await get_auth_token(client, "admin", "testpass1234")

        response = await client.put(
            "/api/admin/users/00000000-0000-0000-0000-000000000000/unblock",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 404

    async def test_regular_user_cannot_unblock(self, client: AsyncClient):
        """Test that regular users cannot unblock."""
        user_token = await get_auth_token(client, "user1", "userpass1234")

        # Try to unblock with regular user token
        response = await client.put(
            "/api/admin/users/00000000-0000-0000-0000-000000000000/unblock",
            headers={"Authorization": f"Bearer {user_token}"}
        )

        assert response.status_code == 403


class TestAdminDeleteUser:
    """Test admin delete user endpoint."""

    async def test_admin_delete_user(self, client: AsyncClient):
        """Test that admin can delete users (DELETE /api/admin/users/{id})."""
        token = await get_auth_token(client, "admin", "testpass1234")

        # Create a test user to delete
        from app.services.user_database import get_user_db_service
        from app.models.user import UserCreate, UserRole
        user_db = get_user_db_service()
        new_user = UserCreate(
            username="deletetest",
            email="deletetest@example.com",
            password="testpass1234"
        )
        created_user = await user_db.create_user(new_user, role=UserRole.USER, auto_approve=True)

        # Delete the user as admin
        delete_response = await client.delete(
            f"/api/admin/users/{created_user.id}",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert delete_response.status_code == 200
        assert "deleted successfully" in delete_response.json()["message"]

        # Verify user cannot login
        login_response = await client.post(
            "/api/token",
            data={"username": "deletetest", "password": "testpass1234"}
        )
        assert login_response.status_code == 401

    async def test_admin_delete_nonexistent_user(self, client: AsyncClient):
        """Test deleting non-existent user returns 404."""
        token = await get_auth_token(client, "admin", "testpass1234")

        response = await client.delete(
            "/api/admin/users/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 404

    async def test_admin_cannot_delete_self(self, client: AsyncClient):
        """Test that admin cannot delete their own account."""
        token = await get_auth_token(client, "admin", "testpass1234")

        # Get admin's user ID
        me_response = await client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        admin_id = me_response.json()["id"]

        # Try to delete self
        response = await client.delete(
            f"/api/admin/users/{admin_id}",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 400
        assert "Cannot delete your own account" in response.json()["detail"]


class TestSessionInvalidation:
    """Test session invalidation scenarios."""

    async def test_inactive_user_session_invalid(self, client: AsyncClient):
        """Test blocked user's session is invalidated (403)."""
        # Create a new user for this test
        from app.services.user_database import get_user_db_service
        from app.models.user import UserCreate, UserRole
        user_db = get_user_db_service()
        new_user = UserCreate(
            username="sessiontest",
            email="sessiontest@example.com",
            password="testpass1234"
        )
        created_user = await user_db.create_user(new_user, role=UserRole.USER, auto_approve=True)

        # User logs in and gets token
        user_token = await get_auth_token(client, "sessiontest", "testpass1234")

        # Verify token works
        response1 = await client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response1.status_code == 200

        # Admin blocks user
        admin_token = await get_auth_token(client, "admin", "testpass1234")
        block_response = await client.put(
            f"/api/admin/users/{created_user.id}/block",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert block_response.status_code == 200

        # User tries to access protected route with old token
        response2 = await client.get(
            "/api/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )

        # Should be denied because user is now inactive
        assert response2.status_code == 403
        assert "inactive" in response2.json()["detail"].lower()

    async def test_unapproved_user_session_invalid(self, client: AsyncClient):
        """Test that unapproved user's session is invalidated when approval is revoked."""
        # The "unapproved" user exists but isn't approved
        # They shouldn't be able to get a token in the first place
        response = await client.post(
            "/api/token",
            data={"username": "unapproved", "password": "unapprovedpass1234"}
        )

        assert response.status_code == 403
        assert "pending approval" in response.json()["detail"].lower()

    async def test_invalid_token_rejected(self, client: AsyncClient):
        """Test that invalid JWT tokens are rejected (401)."""
        response = await client.get(
            "/api/users/me",
            headers={"Authorization": "Bearer invalid.token.here"}
        )

        assert response.status_code == 401
