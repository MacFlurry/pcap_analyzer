import pytest
import uuid
from app.services.database import DatabaseService
from app.services.user_database import UserDatabaseService
from app.models.user import UserCreate, UserRole
from app.models.schemas import TaskStatus
# Fixtures provided by conftest.py

@pytest.fixture
async def task_db(postgres_db_url, apply_migrations):
    service = DatabaseService(database_url=postgres_db_url)
    await service.init_db()
    return service

@pytest.fixture
async def user_db(postgres_db_url, apply_migrations):
    service = UserDatabaseService(database_url=postgres_db_url)
    await service.init_db()
    return service

@pytest.mark.integration
@pytest.mark.asyncio
async def test_task_lifecycle(task_db, user_db):
    """Test full task lifecycle: create, update status, update results."""
    # Create user
    username = f"taskuser_{uuid.uuid4()}"
    user_create = UserCreate(username=username, email=f"{username}@example.com", password="SecurePassword123!")
    user = await user_db.create_user(user_create)
    
    # Create task
    task_id = str(uuid.uuid4())
    filename = "test.pcap"
    file_size = 1024
    
    task = await task_db.create_task(task_id, filename, file_size, owner_id=user.id)
    assert task.task_id == task_id
    assert task.status == TaskStatus.PENDING
    assert task.owner_id == user.id
    
    # Update status
    await task_db.update_status(task_id, TaskStatus.PROCESSING)
    task = await task_db.get_task(task_id)
    assert task.status == TaskStatus.PROCESSING
    
    # Update results
    await task_db.update_status(task_id, TaskStatus.COMPLETED)
    await task_db.update_results(
        task_id, 
        total_packets=100, 
        health_score=95.0, 
        report_html_path="/tmp/report.html", 
        report_json_path="/tmp/report.json"
    )
    
    task = await task_db.get_task(task_id)
    assert task.status == TaskStatus.COMPLETED
    assert task.total_packets == 100
    assert task.health_score == 95.0

@pytest.mark.integration
@pytest.mark.asyncio
async def test_multi_tenant_isolation(task_db, user_db):
    """Test that users can only see their own tasks."""
    # User A
    user_a = await user_db.create_user(UserCreate(username=f"usera_{uuid.uuid4()}", email="a@test.com", password="SecurePassword123!"))
    task_a_id = str(uuid.uuid4())
    await task_db.create_task(task_a_id, "file_a.pcap", 100, owner_id=user_a.id)
    
    # User B
    user_b = await user_db.create_user(UserCreate(username=f"userb_{uuid.uuid4()}", email="b@test.com", password="SecurePassword123!"))
    task_b_id = str(uuid.uuid4())
    await task_db.create_task(task_b_id, "file_b.pcap", 100, owner_id=user_b.id)
    
    # Admin
    admin = await user_db.create_user(UserCreate(username=f"admin_{uuid.uuid4()}", email="admin@test.com", password="SecurePassword123!"), role=UserRole.ADMIN)
    
    # Check User A visibility
    tasks_a = await task_db.get_recent_tasks(limit=100, owner_id=user_a.id)
    task_ids_a = [t.task_id for t in tasks_a]
    assert task_a_id in task_ids_a
    assert task_b_id not in task_ids_a
    
    # Check User B visibility
    tasks_b = await task_db.get_recent_tasks(limit=100, owner_id=user_b.id)
    task_ids_b = [t.task_id for t in tasks_b]
    assert task_b_id in task_ids_b
    assert task_a_id not in task_ids_b
    
    # Check Admin visibility (no owner_id filter)
    tasks_admin = await task_db.get_recent_tasks(limit=100, owner_id=None)
    task_ids_admin = [t.task_id for t in tasks_admin]
    assert task_a_id in task_ids_admin
    assert task_b_id in task_ids_admin

@pytest.mark.integration
@pytest.mark.asyncio
async def test_cascade_delete(task_db, user_db):
    """Test that deleting a user deletes their tasks."""
    user = await user_db.create_user(UserCreate(username=f"deluser_{uuid.uuid4()}", email="del@test.com", password="SecurePassword123!"))
    task_id = str(uuid.uuid4())
    await task_db.create_task(task_id, "file.pcap", 100, owner_id=user.id)
    
    # Verify task exists
    assert await task_db.get_task(task_id) is not None
    
    # Delete user (raw SQL since no delete method in service)
    # Using execute from pool directly
    delete_query = "DELETE FROM users WHERE id = $1"
    # Need to translate query style? DatabasePool.execute handles it if we use translate_query?
    # Or translate_query handles ? -> $1. 
    # Let's use translate_query to be safe/consistent with abstraction.
    # But wait, translate_query takes ? format.
    
    q, p = user_db.pool.translate_query("DELETE FROM users WHERE id = ?", (user.id,))
    await user_db.pool.execute(q, *p)
    
    # Verify user is gone
    assert await user_db.get_user_by_id(user.id) is None
    
    # Verify task is gone
    assert await task_db.get_task(task_id) is None
