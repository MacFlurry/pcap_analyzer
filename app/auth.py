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
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Query, Request, status
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
    - REQUIRED in production: Set SECRET_KEY env var (32+ chars)
    - Development: Auto-generates random key (invalidates tokens on restart)
    - Minimum 32 bytes (256 bits) for HS256

    Raises:
        ValueError: If SECRET_KEY missing in production mode
        ValueError: If SECRET_KEY shorter than 32 characters
    """
    secret_key = os.getenv("SECRET_KEY")
    environment = os.getenv("ENVIRONMENT", "development").lower()

    if not secret_key:
        # Check if running in production mode
        if environment == "production":
            # FAIL HARD in production mode without SECRET_KEY
            error_msg = (
                "🚨 SECURITY ERROR: SECRET_KEY environment variable is not set!\n"
                "Production deployment REQUIRES a persistent SECRET_KEY.\n"
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"\n"
                "Set it via environment variable or Kubernetes secret."
            )
            logger.error(error_msg)
            raise ValueError("SECRET_KEY is required in production mode")

        # Development: generate random key (will be different on each restart)
        print("=" * 80, file=sys.stderr)
        print("⚠️  WARNING: SECRET_KEY not set - generating random key", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print("This is OK for development, but causes issues:", file=sys.stderr)
        print("  - All JWT tokens invalidated on app restart", file=sys.stderr)
        print("  - Users must re-login after every deployment", file=sys.stderr)
        print("", file=sys.stderr)
        print("For production, generate and set a persistent SECRET_KEY:", file=sys.stderr)
        print("  python -c \"import secrets; print(secrets.token_hex(32))\"", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        logger.warning("SECRET_KEY not set, generating random key (development only)")
        secret_key = secrets.token_urlsafe(32)

    if len(secret_key) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters (current length: {})".format(len(secret_key)))

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


async def get_current_user_from_token(token: str, user_db) -> User:
    """Helper to validate token and return user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        secret_key = get_secret_key()
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except (JWTError, ValidationError):
        raise credentials_exception

    user = await user_db.get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Extract and validate current user from JWT token.

    Args:
        token: JWT token from Authorization header

    Returns:
        Current authenticated user

    Raises:
        HTTPException 401: If token is invalid or user doesn't exist
    """
    from app.services.user_database import get_user_db_service

    user_db = get_user_db_service()
    return await get_current_user_from_token(token, user_db)


async def get_current_user_sse(
    request: Request,
    token: Optional[str] = Query(None, description="JWT token for SSE (since EventSource can't send headers)"),
) -> User:
    """
    Extract and validate current user from JWT token for SSE endpoints.

    EventSource API doesn't support custom headers, so we accept token via:
    1. Query parameter ?token=xxx (for SSE compatibility)
    2. Authorization header (fallback for fetch() calls)

    Args:
        request: FastAPI request object
        token: JWT token from query parameter

    Returns:
        Current authenticated user

    Raises:
        HTTPException 401: If token is invalid/expired or user not found

    Security Note:
    - Tokens in URLs are logged by proxies/servers (less secure than headers)
    - Only use for SSE where headers aren't possible
    - Tokens should be short-lived (30 min default)
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Try to get token from query param first, then Authorization header
    if not token:
        # Fallback to Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
        else:
            logger.warning("SSE: No token in query param or Authorization header")
            raise credentials_exception

    try:
        # Decode and validate JWT
        secret_key = get_secret_key()
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])

        # Extract user info from token
        user_id: str = payload.get("sub")
        username: str = payload.get("username")
        role_str: str = payload.get("role")

        if user_id is None or username is None or role_str is None:
            logger.warning("SSE: Invalid token payload (missing fields)")
            raise credentials_exception

        # Create TokenData for validation
        token_data = TokenData(
            sub=user_id,
            username=username,
            role=UserRole(role_str),
            exp=datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc),
        )

    except JWTError as e:
        logger.warning(f"SSE: JWT validation failed: {e}")
        raise credentials_exception

    except ValidationError as e:
        logger.warning(f"SSE: Token data validation failed: {e}")
        raise credentials_exception

    # Get user from database (verify still exists and active)
    user_db = get_user_db_service()
    user = await user_db.get_user_by_id(token_data.sub)

    if user is None:
        logger.warning(f"SSE: User from token not found: {token_data.sub}")
        raise credentials_exception

    if not user.is_active:
        logger.warning(f"SSE: User from token is inactive: {user.username}")
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
