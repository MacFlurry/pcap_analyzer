"""
OAuth2 + JWT Authentication

Implements:
- OAuth2 password flow (RFC 6749)
- JWT token generation/validation (RFC 7519)
- Role-based access control (RBAC)
- Multi-tenant authorization

References:
- RFC 6749: OAuth 2.0 Authorization Framework
- RFC 7519: JSON Web Tokens
- OWASP ASVS 2.2: Session Management
- OWASP ASVS 4.1: Access Control
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError

from app.models.user import TokenData, User, UserRole
from app.services.user_database import get_user_db_service

logger = logging.getLogger(__name__)

# OAuth2 password bearer for token extraction
# tokenUrl: where client gets token (POST /api/token)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# JWT configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def get_secret_key() -> str:
    """
    Get JWT secret key from environment or generate one.

    Returns:
        Secret key (32+ bytes for HS256)

    Security:
    - Use SECRET_KEY env var in production (set in K8s secret)
    - Generate random key if missing (development only)
    - Minimum 32 bytes (256 bits) for HS256
    """
    secret_key = os.getenv("SECRET_KEY")

    if not secret_key:
        # Development: generate random key (will be different on each restart)
        logger.warning("SECRET_KEY not set, generating random key (development only)")
        logger.warning("Set SECRET_KEY env var for production!")
        secret_key = secrets.token_urlsafe(32)

    if len(secret_key) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters")

    return secret_key


def create_access_token(user: User, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token for authenticated user.

    Args:
        user: Authenticated user
        expires_delta: Custom expiration (default: 30 minutes)

    Returns:
        JWT token string

    Token payload (RFC 7519):
    - sub: Subject (user_id)
    - username: Username
    - role: User role (admin/user)
    - exp: Expiration timestamp
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    expire = datetime.now(timezone.utc) + expires_delta

    payload = {
        "sub": user.id,          # Subject: user ID
        "username": user.username,
        "role": user.role.value,
        "exp": expire,           # Expiration
    }

    secret_key = get_secret_key()
    encoded_jwt = jwt.encode(payload, secret_key, algorithm=ALGORITHM)

    logger.info(f"Created access token for user: {user.username} (role: {user.role.value}, expires: {expire})")

    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Extract and validate current user from JWT token.

    Args:
        token: JWT token from Authorization header

    Returns:
        Current authenticated user

    Raises:
        HTTPException 401: If token is invalid/expired or user not found

    Security:
    - Validates JWT signature
    - Checks expiration
    - Verifies user still exists and is active
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode and validate JWT
        secret_key = get_secret_key()
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])

        # Extract user info from token
        user_id: str = payload.get("sub")
        username: str = payload.get("username")
        role_str: str = payload.get("role")

        if user_id is None or username is None or role_str is None:
            logger.warning("Invalid token payload (missing fields)")
            raise credentials_exception

        # Create TokenData for validation
        token_data = TokenData(
            sub=user_id,
            username=username,
            role=UserRole(role_str),
            exp=datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc),
        )

    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise credentials_exception

    except ValidationError as e:
        logger.warning(f"Token data validation failed: {e}")
        raise credentials_exception

    # Get user from database (verify still exists and active)
    user_db = get_user_db_service()
    user = await user_db.get_user_by_id(token_data.sub)

    if user is None:
        logger.warning(f"User from token not found: {token_data.sub}")
        raise credentials_exception

    if not user.is_active:
        logger.warning(f"User from token is inactive: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    return user


async def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Verify current user is an admin.

    Args:
        current_user: Current authenticated user

    Returns:
        Current user (if admin)

    Raises:
        HTTPException 403: If user is not admin

    Usage:
        @app.get("/api/admin/users")
        async def get_all_users(admin: User = Depends(get_current_admin_user)):
            # Only admins can access this endpoint
            ...
    """
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"User {current_user.username} attempted admin-only action (role: {current_user.role.value})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return current_user


def verify_ownership(current_user: User, resource_owner_id: Optional[str]) -> bool:
    """
    Verify user owns resource (multi-tenant check).

    Args:
        current_user: Current authenticated user
        resource_owner_id: Owner ID of resource (from database)

    Returns:
        True if user owns resource OR user is admin

    Usage:
        task = await db.get_task(task_id)
        if not verify_ownership(current_user, task.owner_id):
            raise HTTPException(403, "Access denied")
    """
    # Admin can see everything
    if current_user.role == UserRole.ADMIN:
        return True

    # User can only see own resources
    if resource_owner_id is None:
        # Resource has no owner (legacy data before multi-tenant)
        logger.warning(f"Resource has no owner_id (legacy data)")
        return False

    return current_user.id == resource_owner_id
