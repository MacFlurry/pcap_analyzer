import pytest
import uuid
from app.services.user_database import UserDatabaseService
from app.models.user import UserCreate, UserRole
# Fixtures provided by conftest.py

@pytest.fixture
async def user_db(postgres_db_url, apply_migrations):
    """
    Fixture to provide a UserDatabaseService connected to the test container.
    Ensures migrations are applied.
    """
    service = UserDatabaseService(database_url=postgres_db_url)
    # No need to call init_db() if migrations are applied, but let's be safe as it might do other setup
    # Actually, init_db just logs for Postgres, so it's fine.
    await service.init_db()
    return service

@pytest.mark.integration
@pytest.mark.asyncio
async def test_create_and_get_user(user_db):
    """Test creating a user and retrieving it."""
    username = f"testuser_{uuid.uuid4()}"
    email = f"{username}@example.com"
    password = "SecurePassword123!"
    
    user_create = UserCreate(username=username, email=email, password=password)
    
    # Create user
    user = await user_db.create_user(user_create)
    
    assert user.username == username
    assert user.email == email
    assert user.role == UserRole.USER
    assert user.is_approved is False # Default should be false
    
    # Get by ID
    fetched_user = await user_db.get_user_by_id(user.id)
    assert fetched_user is not None
    assert fetched_user.username == username
    
    # Get by Username
    fetched_user_by_name = await user_db.get_user_by_username(username)
    assert fetched_user_by_name is not None
    assert fetched_user_by_name.id == user.id

@pytest.mark.integration
@pytest.mark.asyncio
async def test_authentication(user_db):
    """Test user authentication."""
    username = f"authuser_{uuid.uuid4()}"
    password = "SecurePassword123!"
    
    user_create = UserCreate(username=username, email=f"{username}@example.com", password=password)
    user = await user_db.create_user(user_create)
    
    # Authenticate - should fail because is_approved is False by default
    auth_user = await user_db.authenticate_user(username, password)
    assert auth_user is None
    
    # Create an admin user to approve
    admin_username = f"admin_{uuid.uuid4()}"
    admin_create = UserCreate(username=admin_username, email=f"{admin_username}@example.com", password="AdminPassword123!")
    admin_user = await user_db.create_user(admin_create, role=UserRole.ADMIN, auto_approve=True)
    
    # Approve user using admin ID
    await user_db.approve_user(user.id, admin_user.id)
    
    # Authenticate - should succeed now
    auth_user = await user_db.authenticate_user(username, password)
    assert auth_user is not None
    assert auth_user.id == user.id
    
    # Authenticate with wrong password
    auth_user = await user_db.authenticate_user(username, "WrongPassword")
    assert auth_user is None

@pytest.mark.integration
@pytest.mark.asyncio
async def test_update_password_and_history(user_db):
    """Test password update and history tracking."""
    username = f"pwduser_{uuid.uuid4()}"
    password_v1 = "PasswordV1_LongEnough!"
    password_v2 = "PasswordV2_LongEnough!"
    
    user_create = UserCreate(username=username, email=f"{username}@example.com", password=password_v1)
    user = await user_db.create_user(user_create)
    
    # Create an admin user to approve
    admin_username = f"admin_pwd_{uuid.uuid4()}"
    admin_create = UserCreate(username=admin_username, email=f"{admin_username}@example.com", password="AdminPassword123!")
    admin_user = await user_db.create_user(admin_create, role=UserRole.ADMIN, auto_approve=True)

    # Approve to allow login checks
    await user_db.approve_user(user.id, admin_user.id)
    
    # Update password
    await user_db.update_password(user.id, password_v2)
    
    # Verify new password works
    auth_user = await user_db.authenticate_user(username, password_v2)
    assert auth_user is not None
    
    # Verify old password fails
    auth_user = await user_db.authenticate_user(username, password_v1)
    assert auth_user is None
    
    # Test password reuse prevention
    with pytest.raises(ValueError, match="Password was used recently"):
        await user_db.update_password(user.id, password_v1)

@pytest.mark.integration
@pytest.mark.asyncio
async def test_admin_actions(user_db):
    """Test blocking and unblocking users."""
    username = f"blockuser_{uuid.uuid4()}"
    user_create = UserCreate(username=username, email=f"{username}@example.com", password="SecurePassword123!")
    user = await user_db.create_user(user_create, auto_approve=True)
    
    # Verify active
    assert user.is_active is True
    
    # Block
    await user_db.block_user(user.id)
    fetched_user = await user_db.get_user_by_id(user.id)
    assert fetched_user.is_active is False
    
    # Authenticate should fail
    auth_user = await user_db.authenticate_user(username, "SecurePassword123!")
    assert auth_user is None
    
    # Unblock
    await user_db.unblock_user(user.id)
    fetched_user = await user_db.get_user_by_id(user.id)
    assert fetched_user.is_active is True
    
    # Authenticate should succeed
    auth_user = await user_db.authenticate_user(username, "SecurePassword123!")
    assert auth_user is not None

@pytest.mark.integration
@pytest.mark.asyncio
async def test_jwt_persistence(user_db, monkeypatch):
    """
    Test JWT token creation and validation persistence.
    Verifies that a token issued continues to work as long as the user exists in DB.
    """
    from app.auth import create_access_token, get_current_user, get_secret_key
    from starlette.requests import Request
    from datetime import timedelta
    
    # Ensure SECRET_KEY is set for consistency
    monkeypatch.setenv("SECRET_KEY", "test_secret_key_must_be_long_enough_32_bytes")
    
    username = f"jwtuser_{uuid.uuid4()}"
    user_create = UserCreate(username=username, email=f"{username}@example.com", password="SecurePassword123!")
    # Create approved user
    user = await user_db.create_user(user_create, auto_approve=True)
    
    # 1. Create Token
    token = create_access_token(user, expires_delta=timedelta(minutes=5))
    assert token is not None
    
    # 2. Validate Token (simulate dependency injection)
    # get_current_user imports get_user_db_service from the service module at runtime.
    import app.services.user_database
    monkeypatch.setattr(app.services.user_database, "get_user_db_service", lambda: user_db)
    
    request = Request({"type": "http", "headers": [], "query_string": b""})
    authenticated_user = await get_current_user(request=request, token=token)
    assert authenticated_user is not None
    assert authenticated_user.id == user.id
    assert authenticated_user.username == username
    
    # 3. Test persistence across DB interactions
    # Modify user in DB (e.g., update last login)
    await user_db.update_last_login(user.id)
    
    # Token should still be valid and return updated user info (if any)
    authenticated_user_2 = await get_current_user(request=request, token=token)
    assert authenticated_user_2.last_login is not None
    
    # 4. Test invalidation on user deletion
    # Delete user using raw SQL since delete_user isn't in service yet (or use block)
    # Actually, let's block the user and see if token is rejected (logic in get_current_user checks is_active)
    await user_db.block_user(user.id)
    
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request=request, token=token)
    assert exc.value.status_code == 403
    assert "inactive" in exc.value.detail
