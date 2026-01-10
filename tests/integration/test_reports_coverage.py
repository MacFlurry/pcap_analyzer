import pytest
import os
import uuid
from pathlib import Path
from httpx import AsyncClient
from app.models.schemas import TaskStatus
from app.services.database import get_db_service
from app.services.user_database import get_user_db_service
from app.models.user import UserCreate, UserRole

@pytest.mark.integration
async def test_get_reports_success(api_client, auth_headers, auth_user, test_data_dir):
    """Test successful retrieval of HTML and JSON reports."""
    db = get_db_service()
    task_id = str(uuid.uuid4())
    
    # Create actual dummy files
    reports_dir = test_data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f"{task_id}.html").write_text("<html><body>Test Report</body></html>")
    (reports_dir / f"{task_id}.json").write_text('{"test": "data"}')
    
    await db.create_task(
        task_id=task_id,
        filename="test.pcap",
        file_size_bytes=100,
        owner_id=auth_user.id
    )
    await db.update_status(task_id=task_id, status=TaskStatus.COMPLETED)
    await db.update_results(
        task_id=task_id,
        total_packets=10,
        health_score=100.0,
        report_html_path=f"{task_id}.html",
        report_json_path=f"{task_id}.json"
    )
    
    # Get HTML report
    response = await api_client.get(f"/api/reports/{task_id}/html", headers=auth_headers)
    assert response.status_code == 200
    assert "Test Report" in response.text
    
    # Get JSON report
    response = await api_client.get(f"/api/reports/{task_id}/json", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {"test": "data"}

@pytest.mark.integration
async def test_reports_multi_tenant_isolation(api_client, auth_headers, test_data_dir):
    """Test that users cannot access reports of other users."""
    db = get_db_service()
    udb = get_user_db_service()
    
    # Create another user
    username = f"otheruser_{uuid.uuid4().hex[:8]}"
    other_user = await udb.create_user(
        UserCreate(username=username, email=f"{username}@example.com", password="SecurePassword123!"),
        auto_approve=True
    )
    
    task_id = str(uuid.uuid4())
    
    reports_dir = test_data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f"{task_id}.html").write_text("<html><body>Other User Report</body></html>")
    
    await db.create_task(
        task_id=task_id,
        filename="other.pcap",
        file_size_bytes=100,
        owner_id=other_user.id
    )
    await db.update_status(task_id=task_id, status=TaskStatus.COMPLETED)
    await db.update_results(
        task_id=task_id,
        total_packets=10,
        health_score=100.0,
        report_html_path=f"{task_id}.html",
        report_json_path=f"{task_id}.json"
    )
    
    # Try to access other user's report with auth_headers (first user)
    response = await api_client.get(f"/api/reports/{task_id}/html", headers=auth_headers)
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]

@pytest.mark.integration
async def test_admin_access_all_reports(api_client, test_data_dir):
    """Test that admins can access any report."""
    db = get_db_service()
    udb = get_user_db_service()
    
    # Create an admin
    admin_name = f"admin_{uuid.uuid4().hex[:8]}"
    admin_user = await udb.create_user(
        UserCreate(username=admin_name, email=f"{admin_name}@example.com", password="SecurePassword123!"),
        role=UserRole.ADMIN,
        auto_approve=True
    )
    from app.auth import create_access_token
    admin_token = create_access_token(admin_user)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Create a task for a regular user
    reg_name = f"reg_{uuid.uuid4().hex[:8]}"
    reg_user = await udb.create_user(
        UserCreate(username=reg_name, email=f"{reg_name}@example.com", password="SecurePassword123!"),
        auto_approve=True
    )
    
    task_id = str(uuid.uuid4())
    
    reports_dir = test_data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f"{task_id}.html").write_text("<html><body>Regular User Report</body></html>")
    
    await db.create_task(
        task_id=task_id,
        filename="reg.pcap",
        file_size_bytes=100,
        owner_id=reg_user.id
    )
    await db.update_status(task_id=task_id, status=TaskStatus.COMPLETED)
    await db.update_results(
        task_id=task_id,
        total_packets=10,
        health_score=100.0,
        report_html_path=f"{task_id}.html",
        report_json_path=f"{task_id}.json"
    )
    
    # Admin access
    response = await api_client.get(f"/api/reports/{task_id}/html", headers=admin_headers)
    assert response.status_code == 200
    assert "Regular User Report" in response.text

@pytest.mark.integration
async def test_report_not_found(api_client, auth_headers):
    """Test error cases for nonexistent tasks or files."""
    # Nonexistent task ID
    response = await api_client.get(f"/api/reports/{uuid.uuid4()}/html", headers=auth_headers)
    assert response.status_code == 404
    
@pytest.mark.integration
async def test_delete_report(api_client, auth_headers, auth_user, test_data_dir, csrf_token):
    """Test report deletion."""
    db = get_db_service()
    task_id = str(uuid.uuid4())
    
    reports_dir = test_data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    html_file = reports_dir / f"{task_id}.html"
    json_file = reports_dir / f"{task_id}.json"
    html_file.write_text("Delete me HTML")
    json_file.write_text("Delete me JSON")
    
    await db.create_task(task_id=task_id, filename="delete.pcap", file_size_bytes=100, owner_id=auth_user.id)
    await db.update_status(task_id=task_id, status=TaskStatus.COMPLETED)
    await db.update_results(
        task_id=task_id,
        total_packets=10,
        health_score=100.0,
        report_html_path=f"{task_id}.html",
        report_json_path=f"{task_id}.json"
    )
    
    assert html_file.exists()
    assert json_file.exists()
    
    headers = auth_headers.copy()
    headers["X-CSRF-Token"] = csrf_token
    
    response = await api_client.delete(f"/api/reports/{task_id}", headers=headers)
    assert response.status_code == 200
    assert "deleted" in response.json()["message"]
    
    # Verify files deleted
    assert not html_file.exists()
    assert not json_file.exists()
    # Verify DB marked as expired
    task = await db.get_task(task_id)
    assert task.status == TaskStatus.EXPIRED.value
