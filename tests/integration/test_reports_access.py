"""
Tests d'intégration pour l'accès aux rapports et l'isolation multi-tenant.
"""

import pytest
import uuid
from fastapi import status
from app.models.user import UserRole, UserCreate
from app.auth import create_access_token

@pytest.fixture
async def approved_user_b(user_db):
    """Create a second approved test user."""
    username = f"user_b_{uuid.uuid4().hex[:8]}"
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
def auth_headers_b(approved_user_b):
    """Headers for user B."""
    token = create_access_token(approved_user_b)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
async def admin_user(user_db):
    """Create an admin user."""
    username = f"admin_{uuid.uuid4().hex[:8]}"
    user = await user_db.create_user(
        UserCreate(
            username=username,
            email=f"{username}@example.com",
            password="AdminPassword123!"
        ),
        auto_approve=True
    )
    # Update role to admin manually since create_user might default to 'user'
    await user_db.pool.execute(
        "UPDATE users SET role = $1 WHERE id = $2",
        UserRole.ADMIN, user.id
    )
    user.role = UserRole.ADMIN
    return user

@pytest.fixture
def admin_headers(admin_user):
    """Headers for admin user."""
    token = create_access_token(admin_user)
    return {"Authorization": f"Bearer {token}"}

@pytest.mark.integration
@pytest.mark.asyncio
async def test_report_access_isolation(api_client, test_db, auth_user, auth_headers, auth_headers_b, admin_headers, test_data_dir):
    """
    Test multi-tenant isolation for report access.
    """
    task_id = str(uuid.uuid4())
    reports_dir = test_data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Create a task owned by user A
    await test_db.create_task(
        task_id=task_id,
        filename="test.pcap",
        file_size_bytes=100,
        owner_id=auth_user.id
    )
    
    # Create dummy report files
    html_file = reports_dir / f"{task_id}.html"
    json_file = reports_dir / f"{task_id}.json"
    html_file.write_text("<html><body>Test Report</body></html>")
    json_file.write_text('{"test": true}')
    
    # 2. User A (owner) accesses their report -> 200
    response = await api_client.get(f"/api/reports/{task_id}/html", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    assert "Test Report" in response.text
    
    # 3. User B (non-owner) tries to access User A's report -> 403
    response = await api_client.get(f"/api/reports/{task_id}/html", headers=auth_headers_b)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Access denied" in response.json()["detail"]
    
    # 4. Admin accesses User A's report -> 200
    response = await api_client.get(f"/api/reports/{task_id}/html", headers=admin_headers)
    assert response.status_code == status.HTTP_200_OK
    
    # 5. Non-existent task -> 404
    fake_id = str(uuid.uuid4())
    response = await api_client.get(f"/api/reports/{fake_id}/html", headers=auth_headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND

@pytest.mark.integration
@pytest.mark.asyncio
async def test_report_deletion_isolation(api_client, test_db, auth_user, auth_headers, auth_headers_b, admin_headers, test_data_dir):
    """
    Test multi-tenant isolation for report deletion.
    """
    task_id = str(uuid.uuid4())
    reports_dir = test_data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Create task and files
    await test_db.create_task(task_id=task_id, filename="test.pcap", file_size_bytes=100, owner_id=auth_user.id)
    (reports_dir / f"{task_id}.html").write_text("...")
    (reports_dir / f"{task_id}.json").write_text("...")
    
    # Need CSRF for DELETE
    csrf_resp = await api_client.get("/api/csrf/token", headers=auth_headers_b)
    csrf_token_b = csrf_resp.json()["csrf_token"]
    headers_b = auth_headers_b.copy()
    headers_b["X-CSRF-Token"] = csrf_token_b
    
    # 1. User B tries to delete User A's report -> 403
    response = await api_client.delete(f"/api/reports/{task_id}", headers=headers_b)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert (reports_dir / f"{task_id}.html").exists()
    
    # 2. User A deletes their own report -> 200
    csrf_resp = await api_client.get("/api/csrf/token", headers=auth_headers)
    csrf_token_a = csrf_resp.json()["csrf_token"]
    headers_a = auth_headers.copy()
    headers_a["X-CSRF-Token"] = csrf_token_a
    
    response = await api_client.delete(f"/api/reports/{task_id}", headers=headers_a)
    assert response.status_code == status.HTTP_200_OK
    assert not (reports_dir / f"{task_id}.html").exists()
