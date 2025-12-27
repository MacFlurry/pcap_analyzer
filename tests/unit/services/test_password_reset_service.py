"""
Unit tests for PasswordResetService.
"""

import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, AsyncMock

from app.services.password_reset_service import PasswordResetService
from app.models.user import User, UserRole

@pytest.fixture
def mock_db_pool():
    with patch("app.services.password_reset_service.DatabasePool") as mock:
        pool = mock.return_value
        pool.execute = AsyncMock()
        pool.fetch_one = AsyncMock()
        pool.fetch_all = AsyncMock()
        pool.translate_query = MagicMock(side_effect=lambda q, p: (q.replace("?", "%s"), p))
        yield pool

@pytest.fixture
def service(mock_db_pool):
    return PasswordResetService()

@pytest.mark.asyncio
async def test_generate_reset_token(service):
    """Test token generation returns plaintext and hash."""
    plaintext, token_hash = service.generate_reset_token()
    
    assert plaintext is not None
    assert token_hash is not None
    assert len(plaintext) >= 32
    assert len(token_hash) == 64  # SHA-256 hex
    
    # Test deterministic hashing
    import hashlib
    expected_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    assert token_hash == expected_hash

@pytest.mark.asyncio
async def test_create_reset_token(service, mock_db_pool):
    """Test creating a reset token in the database."""
    user_id = "test-user-id"
    ip = "127.0.0.1"
    ua = "test-ua"
    
    plaintext = await service.create_reset_token(user_id, ip, ua)
    
    assert plaintext is not None
    assert mock_db_pool.execute.called
    
    # Check parameters
    args, _ = mock_db_pool.execute.call_args
    params = args[1:] # First arg is query
    # Since we use translate_query, params are passed as *params
    # Wait, execute(query, *params)
    # So args[0] is query, args[1:] are params
    
    flat_params = []
    for p in args[1:]:
        flat_params.append(p)
        
    assert user_id in flat_params
    assert ip in flat_params
    assert ua in flat_params

@pytest.mark.asyncio
async def test_validate_token_success(service, mock_db_pool):
    """Test validation of a valid token."""
    token_hash = "valid-hash"
    user_id = "user-123"
    
    # Mock finding a valid token
    mock_db_pool.fetch_one.return_value = {
        "user_id": user_id,
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    }
    
    # Mock finding the user
    with patch("app.services.password_reset_service.get_user_db_service") as mock_user_db:
        mock_user_db.return_value.get_user_by_id = AsyncMock()
        mock_user_db.return_value.get_user_by_id.return_value = User(
            id=user_id, username="test", email="test@example.com", hashed_password="...", 
            is_active=True, is_approved=True, created_at=datetime.now(timezone.utc)
        )
        
        user = await service.validate_token(token_hash)
        
        assert user is not None
        assert user.id == user_id

@pytest.mark.asyncio
async def test_validate_token_expired(service, mock_db_pool):
    """Test validation of an expired token."""
    token_hash = "expired-hash"
    
    mock_db_pool.fetch_one.return_value = {
        "user_id": "user-123",
        "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    }
    
    user = await service.validate_token(token_hash)
    assert user is None

@pytest.mark.asyncio
async def test_validate_token_not_found(service, mock_db_pool):
    """Test validation of a non-existent token."""
    token_hash = "missing-hash"
    
    mock_db_pool.fetch_one.return_value = None
    
    user = await service.validate_token(token_hash)
    assert user is None

@pytest.mark.asyncio
async def test_consume_token(service, mock_db_pool):
    """Test marking a token as used."""
    token_hash = "token-to-consume"
    
    success = await service.consume_token(token_hash)
    
    assert success is True
    assert mock_db_pool.execute.called

@pytest.mark.asyncio

async def test_validate_token_inactive_user(service, mock_db_pool):

    """Test validation fails if user is inactive."""

    token_hash = "valid-hash"

    user_id = "user-123"

    

    mock_db_pool.fetch_one.return_value = {

        "user_id": user_id,

        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    }

    

    with patch("app.services.password_reset_service.get_user_db_service") as mock_user_db:

        # User is inactive

        mock_user_db.return_value.get_user_by_id = AsyncMock()

        mock_user_db.return_value.get_user_by_id.return_value = User(

            id=user_id, username="test", email="test@example.com", hashed_password="...", 

            is_active=False, is_approved=True, created_at=datetime.now(timezone.utc)

        )

        

        user = await service.validate_token(token_hash)

        assert user is None



@pytest.mark.asyncio

async def test_invalidate_user_tokens(service, mock_db_pool):

    """Test invalidating all tokens for a user."""

    user_id = "user-123"

    await service.invalidate_user_tokens(user_id)

    assert mock_db_pool.execute.called



@pytest.mark.asyncio

async def test_singleton_instance():

    """Test get_password_reset_service returns singleton."""

    from app.services.password_reset_service import get_password_reset_service

    s1 = get_password_reset_service()

    s2 = get_password_reset_service()

    assert s1 is s2
