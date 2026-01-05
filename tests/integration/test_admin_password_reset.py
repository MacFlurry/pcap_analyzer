"""
Integration tests for Admin Password Reset API endpoint.
"""

import pytest
from unittest.mock import AsyncMock
from app.models.user import User, UserRole
from app.main import app
from app.services.email_service import get_email_service
import uuid

@pytest.fixture
def mock_email_service():
    mock_service = AsyncMock()
    app.dependency_overrides[get_email_service] = lambda: mock_service
    yield mock_service
    del app.dependency_overrides[get_email_service]

@pytest.mark.asyncio
async def test_admin_reset_user_password_success(api_client, auth_headers, auth_user, mock_email_service):
    """Test admin resetting a user password (sending email)."""
    # Create admin user
    from app.services.user_database import get_user_db_service
    from app.auth import create_access_token
    from app.models.user import UserCreate
    
    user_db = get_user_db_service()
    unique_id = uuid.uuid4().hex[:8]
    admin = await user_db.create_user(
        UserCreate(username=f"admin_{unique_id}", email=f"admin_{unique_id}@test.com", password="AdminPassword123!"),
        role=UserRole.ADMIN,
        auto_approve=True
    )
    admin_token = create_access_token(admin)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    
    response = await api_client.post(
        f"/api/admin/users/{auth_user.id}/reset-password",
        headers=admin_headers,
        json={"send_email": True, "notify_user": True}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "Password reset email sent" in data["message"]
    assert "temporary_password" not in data # Should not return password if email sent
    
    # Verify email sent
    assert mock_email_service.send_admin_password_reset_email.called
    
    # Verify user must change password
    updated_user = await user_db.get_user_by_id(auth_user.id)
    assert updated_user.password_must_change is True

@pytest.mark.asyncio
async def test_admin_reset_user_password_no_email(api_client, auth_user):
    """Test admin resetting a user password (returning temp password)."""
    # Create admin user
    from app.services.user_database import get_user_db_service
    from app.auth import create_access_token
    from app.models.user import UserCreate, UserRole
    
    user_db = get_user_db_service()
    unique_id = uuid.uuid4().hex[:8]
    admin = await user_db.create_user(
        UserCreate(username=f"admin_{unique_id}", email=f"admin_{unique_id}@test.com", password="AdminPassword123!"),
        role=UserRole.ADMIN,
        auto_approve=True
    )
    admin_token = create_access_token(admin)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    
    response = await api_client.post(
        f"/api/admin/users/{auth_user.id}/reset-password",
        headers=admin_headers,
        json={"send_email": False, "notify_user": False}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "temporary_password" in data
    assert len(data["temporary_password"]) >= 12
    
    # Verify password updated
    updated_user = await user_db.get_user_by_id(auth_user.id)
    assert user_db.verify_password(data["temporary_password"], updated_user.hashed_password)

@pytest.mark.asyncio
async def test_admin_reset_admin_password_forbidden(api_client, auth_user):
    """Test admin cannot reset another admin's password."""
    from app.services.user_database import get_user_db_service
    user_db = get_user_db_service()
    from app.models.user import UserCreate, UserRole
    from app.auth import create_access_token
    
    # Create 2 admins
    unique_id1 = uuid.uuid4().hex[:8]
    admin1 = await user_db.create_user(
        UserCreate(username=f"admin_{unique_id1}", email=f"admin_{unique_id1}@test.com", password="AdminPassword123!"),
        role=UserRole.ADMIN,
        auto_approve=True
    )
    unique_id2 = uuid.uuid4().hex[:8]
    admin2 = await user_db.create_user(
        UserCreate(username=f"admin_{unique_id2}", email=f"admin_{unique_id2}@test.com", password="AdminPassword123!"),
        role=UserRole.ADMIN,
        auto_approve=True
    )
    
    admin1_token = create_access_token(admin1)
    admin1_headers = {"Authorization": f"Bearer {admin1_token}"}
    
    response = await api_client.post(
        f"/api/admin/users/{admin2.id}/reset-password",
        headers=admin1_headers,
        json={"send_email": False}
    )
    
    assert response.status_code == 403
    assert "Cannot reset another admin" in response.json()["detail"]

@pytest.mark.asyncio
async def test_user_reset_password_forbidden(api_client, auth_user, auth_headers):
    """Test regular user cannot access admin reset endpoint."""
    response = await api_client.post(
        f"/api/admin/users/{auth_user.id}/reset-password",
        headers=auth_headers,
        json={"send_email": False}
    )
    
    assert response.status_code == 403
