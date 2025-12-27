"""
Integration tests for history API endpoints.
Verifies owner_username field visibility for admins and users.
"""

import pytest
import uuid
from app.models.user import UserCreate, UserRole
from app.auth import create_access_token

@pytest.fixture
async def test_users(user_db):
    """Create a regular user and an admin user."""
    # Regular User
    username1 = f"user1_{uuid.uuid4().hex[:8]}"
    user1 = await user_db.create_user(
        UserCreate(username=username1, email=f"{username1}@example.com", password="SecurePassword123!"), 
        auto_approve=True,
        role=UserRole.USER
    )
    
    # Admin User
    admin_name = f"admin_{uuid.uuid4().hex[:8]}"
    admin = await user_db.create_user(
        UserCreate(username=admin_name, email=f"{admin_name}@example.com", password="SecurePassword123!"), 
        auto_approve=True,
        role=UserRole.ADMIN
    )
    
    return {"user1": user1, "admin": admin}

@pytest.fixture
def user_client(api_client, test_users):
    """Client authenticated as regular user."""
    token = create_access_token(test_users["user1"])
    api_client.headers.update({"Authorization": f"Bearer {token}"})
    return api_client

@pytest.fixture
def admin_client(api_client, test_users):
    """Client authenticated as admin user."""
    token = create_access_token(test_users["admin"])
    # Create a NEW client instance or reset headers to avoid conflict?
    # Actually api_client fixture yields a client. Modifying it in place is tricky if used by both fixtures.
    # But usually pytest runs tests sequentially.
    # To be safe, let's just use headers per request or update in place.
    # The fixture above modifies the passed client.
    api_client.headers.update({"Authorization": f"Bearer {token}"})
    return api_client

@pytest.mark.asyncio
async def test_admin_get_history_with_owner_username(api_client, test_users, task_db):
    """Admin should see owner_username in task history."""
    user1 = test_users["user1"]
    admin = test_users["admin"]
    
    # Create task for user1
    task_id = str(uuid.uuid4())
    await task_db.create_task(
        task_id=task_id,
        filename="user1_capture.pcap",
        file_size_bytes=1024,
        owner_id=user1.id
    )
    
    # Authenticate as admin
    token = create_access_token(admin)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Fetch history
    response = await api_client.get("/api/history", headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    # Find the task
    task = next((t for t in data["tasks"] if t["task_id"] == task_id), None)
    assert task is not None
    
    # Verify owner_username is present and correct
    assert "owner_username" in task
    assert task["owner_username"] == user1.username
    assert task["owner_id"] == str(user1.id)

@pytest.mark.asyncio
async def test_user_get_history_with_owner_username(api_client, test_users, task_db):
    """Regular user should also see owner_username (their own)."""
    user1 = test_users["user1"]
    
    # Create task for user1
    task_id = str(uuid.uuid4())
    await task_db.create_task(
        task_id=task_id,
        filename="my_capture.pcap",
        file_size_bytes=1024,
        owner_id=user1.id
    )
    
    # Authenticate as user1
    token = create_access_token(user1)
    headers = {"Authorization": f"Bearer {token}"}
    
    response = await api_client.get("/api/history", headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    task = next((t for t in data["tasks"] if t["task_id"] == task_id), None)
    assert task is not None
    
    # Should see own username
    assert task["owner_username"] == user1.username
