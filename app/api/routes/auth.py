"""
Authentication API endpoints.

Endpoints:
- POST /api/token: Login (OAuth2 password flow)
- POST /api/register: User registration
- GET /api/users/me: Get current user info
- PUT /api/users/me: Update password
- GET /api/users: List all users (admin only)

References:
- RFC 6749 Section 4.3: Resource Owner Password Credentials Grant
- OWASP ASVS 2.1: Password Security
- OWASP ASVS 3.2: Session Management
"""

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field

from app.auth import create_access_token, get_current_admin_user, get_current_user
from app.models.user import Token, User, UserCreate, UserResponse, UserRole
from app.services.user_database import get_user_db_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["auth"])


class PasswordUpdate(BaseModel):
    """Schema for password update."""

    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=12, max_length=128)


@router.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login endpoint (OAuth2 password flow).

    Args:
        form_data: OAuth2 form with username and password

    Returns:
        Access token (JWT)

    Raises:
        HTTPException 401: If credentials are invalid

    Usage (cURL):
        curl -X POST http://localhost:8000/api/token \\
             -H "Content-Type: application/x-www-form-urlencoded" \\
             -d "username=admin&password=your_password"

    Usage (JavaScript):
        const formData = new FormData();
        formData.append('username', 'admin');
        formData.append('password', 'your_password');

        const response = await fetch('/api/token', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        localStorage.setItem('access_token', data.access_token);
    """
    user_db = get_user_db_service()

    # Authenticate user
    user = await user_db.authenticate_user(form_data.username, form_data.password)

    if not user:
        logger.warning(f"Failed login attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create access token
    access_token = create_access_token(user)

    logger.info(f"User logged in: {user.username} (role: {user.role.value})")

    return Token(access_token=access_token, token_type="bearer", expires_in=1800)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """
    User registration endpoint.

    Args:
        user_data: User registration data (username, email, password)

    Returns:
        Created user (without password)

    Raises:
        HTTPException 400: If username/email already exists or password is weak

    Security:
    - Password must be 12+ characters (NIST SP 800-63B)
    - No complexity requirements (counter-productive per NIST)
    - Check against common passwords
    - Bcrypt hashing with cost factor 12

    Usage (JavaScript):
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: 'newuser',
                email: 'user@example.com',
                password: 'secure_password_123'
            })
        });
    """
    user_db = get_user_db_service()

    try:
        # Create user (as regular user, not admin)
        user = await user_db.create_user(user_data, role=UserRole.USER)

        logger.info(f"New user registered: {user.username}")

        # Return user without password
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login=user.last_login,
        )

    except ValueError as e:
        # Username or email already exists
        logger.warning(f"Registration failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current user info.

    Args:
        current_user: Current authenticated user (from JWT token)

    Returns:
        User info (without password)

    Requires:
        Authorization header with Bearer token

    Usage (JavaScript):
        const token = localStorage.getItem('access_token');
        const response = await fetch('/api/users/me', {
            headers: {'Authorization': `Bearer ${token}`}
        });
        const user = await response.json();
    """
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
    )


@router.put("/users/me", response_model=UserResponse)
async def update_password(
    password_update: PasswordUpdate,
    current_user: User = Depends(get_current_user),
):
    """
    Update current user's password.

    Args:
        password_update: Current and new password
        current_user: Current authenticated user

    Returns:
        Updated user info

    Raises:
        HTTPException 401: If current password is incorrect
        HTTPException 400: If new password is weak

    Usage (JavaScript):
        const token = localStorage.getItem('access_token');
        const response = await fetch('/api/users/me', {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                current_password: 'old_password',
                new_password: 'new_secure_password_123'
            })
        });
    """
    user_db = get_user_db_service()

    # Verify current password
    if not user_db.verify_password(password_update.current_password, current_user.hashed_password):
        logger.warning(f"Password update failed for {current_user.username}: incorrect current password")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect current password",
        )

    # Validate new password (min 12 chars)
    if len(password_update.new_password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 12 characters",
        )

    # Update password in database
    await user_db.update_password(current_user.id, password_update.new_password)

    logger.info(f"Password updated for user: {current_user.username}")
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
    )


@router.get("/users", response_model=List[UserResponse])
async def get_all_users(
    admin: User = Depends(get_current_admin_user),
    limit: int = 100,
):
    """
    Get all users (admin only).

    Args:
        admin: Current admin user
        limit: Maximum users to return (default: 100)

    Returns:
        List of all users (without passwords)

    Requires:
        Admin role

    Usage (JavaScript):
        const token = localStorage.getItem('access_token');
        const response = await fetch('/api/users?limit=50', {
            headers: {'Authorization': `Bearer ${token}`}
        });
        const users = await response.json();
    """
    user_db = get_user_db_service()
    users = await user_db.get_all_users(limit=limit)

    logger.info(f"Admin {admin.username} fetched {len(users)} users")

    # Return users without passwords
    return [
        UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login=user.last_login,
        )
        for user in users
    ]
