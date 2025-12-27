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

@pytest.mark.asyncio
async def test_reset_password_success(api_client, auth_user, mock_email_service):
    """Test resetting password with a valid token."""
    from app.services.password_reset_service import get_password_reset_service
    
    # 1. Create a valid token directly
    service = get_password_reset_service()
    token = await service.create_reset_token(auth_user.id, "127.0.0.1", "TestAgent")
    
    # 2. Reset password
    new_password = "NewStrongPassword123!"
    response = await api_client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": new_password
    })
    
    assert response.status_code == 200
    assert response.json()["message"] == "Password reset successful. You can now login with your new password."
    
    # 3. Verify login works with new password
    login_response = await api_client.post("/api/token", data={
        "username": auth_user.username,
        "password": new_password
    })
    assert login_response.status_code == 200
    
    # 4. Verify token is consumed (cannot be reused)
    response_retry = await api_client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": "AnotherPassword123!"
    })
    assert response_retry.status_code == 400
    
    # 5. Verify email sent
    assert mock_email_service.send_password_reset_success_email.called

@pytest.mark.asyncio
async def test_reset_password_invalid_token(api_client):
    """Test reset with invalid token."""
    response = await api_client.post("/api/auth/reset-password", json={
        "token": "invalid_token_string",
        "new_password": "NewStrongPassword123!"
    })
    assert response.status_code == 400
    assert "Invalid or expired token" in response.json()["detail"]

@pytest.mark.asyncio
async def test_reset_password_weak_password(api_client, auth_user):
    """Test reset with weak password."""
    # Create token
    from app.services.password_reset_service import get_password_reset_service
    service = get_password_reset_service()
    token = await service.create_reset_token(auth_user.id)
    
    response = await api_client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": "weak"
    })
    
    # FastAPI returns 422 for Pydantic validation errors
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert any("at least 12 characters" in err["msg"] for err in errors)

@pytest.mark.asyncio
async def test_reset_password_history_reuse(api_client, auth_user):
    """Test reset preventing reuse of old password."""
    from app.services.password_reset_service import get_password_reset_service
    service = get_password_reset_service()
    token = await service.create_reset_token(auth_user.id)
    
    # Use same password as current
    response = await api_client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": "SecurePassword123!" # Default in auth_user fixture
    })
    
    assert response.status_code == 400
    assert "Password was used recently" in response.json()["detail"]