"""
Integration tests for Password Reset API endpoints.
"""

import pytest
from unittest.mock import patch, AsyncMock
from app.models.user import User

from app.main import app
from app.services.email_service import get_email_service

@pytest.fixture
def mock_email_service():
    mock_service = AsyncMock()
    app.dependency_overrides[get_email_service] = lambda: mock_service
    yield mock_service
    del app.dependency_overrides[get_email_service]

@pytest.mark.asyncio
async def test_forgot_password_success(api_client, auth_user, mock_email_service):
    """Test requesting a password reset for an existing user."""
    # Ensure user exists and is approved
    assert auth_user.is_approved
    
    response = await api_client.post("/api/auth/forgot-password", json={"email": auth_user.email})
    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    
    # Verify email service was called
    assert mock_email_service.send_password_reset_request_email.called
    args, _ = mock_email_service.send_password_reset_request_email.call_args
    assert args[0].email == auth_user.email

@pytest.mark.asyncio
async def test_forgot_password_unknown_email(api_client, mock_email_service):
    """Test requesting a password reset for a non-existent email (should return 200 for security)."""
    response = await api_client.post("/api/auth/forgot-password", json={"email": "nonexistent@example.com"})
    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    
    # Verify email service was NOT called
    assert not mock_email_service.send_password_reset_request_email.called

@pytest.mark.asyncio
async def test_forgot_password_rate_limiting(api_client, auth_user, mock_email_service):
    """Test rate limiting on forgot-password endpoint."""
    # RateLimiter allows 4 attempts before lockout (exponential backoff starts at 4th failure)
    # Since we record failure on every request, we can make 4 requests.
    # The 5th request should fail.
    
    for _ in range(4):
        response = await api_client.post("/api/auth/forgot-password", json={"email": auth_user.email})
        assert response.status_code == 200
        
    # 5th request should fail
    response = await api_client.post("/api/auth/forgot-password", json={"email": auth_user.email})
    assert response.status_code == 429
