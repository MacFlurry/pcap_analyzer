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
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError

from app.models.user import TokenData, User, UserRole
from app.services.user_database import get_user_db_service

logger = logging.getLogger(__name__)

# OAuth2 password bearer for token extraction
# tokenUrl: where client gets token (POST /api/token)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token", auto_error=False)

# JWT configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def get_token_from_request(request: Request, token: Optional[str] = None) -> Optional[str]:
    """
    Extract token from multiple sources:
    1. Direct argument (e.g. from oauth2_scheme)
    2. Authorization Header (if not already extracted)
    3. access_token Cookie
    """
    if token:
        return token

    # 1. Check Authorization Header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "")

    # 2. Check Cookie
    return request.cookies.get("access_token")


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


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme)
) -> User:
    """
    Extract and validate current user from JWT token (Header or Cookie).

    Args:
        request: FastAPI request object
        token: JWT token (auto-extracted by oauth2_scheme if present in header)

    Returns:
        Current authenticated user

    Raises:
        HTTPException 401: If token is missing, invalid, or user doesn't exist
    """
    effective_token = get_token_from_request(request, token)
    
    if not effective_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from app.services.user_database import get_user_db_service
    user_db = get_user_db_service()
    return await get_current_user_from_token(effective_token, user_db)


async def get_current_user_optional(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme)
) -> Optional[User]:
    """
    Optional version of get_current_user. Does not raise 401 if missing.
    Returns None if unauthenticated or token invalid.
    """
    effective_token = get_token_from_request(request, token)
    if not effective_token:
        return None

    try:
        from app.services.user_database import get_user_db_service
        user_db = get_user_db_service()
        return await get_current_user_from_token(effective_token, user_db)
    except HTTPException:
        return None


async def get_current_user_cookie_or_redirect(
    request: Request,
    user: Optional[User] = Depends(get_current_user_optional)
) -> User:
    """
    Dependency for HTML routes.
    If not authenticated, returns a RedirectResponse to /login.
    Otherwise returns the User.
    
    NOTE: This must be handled carefully in routes as it might return 
    a RedirectResponse instead of a User if not caught by a custom exception.
    """
    if not user:
        # Construct returnUrl
        return_url = request.url.path
        if request.url.query:
            return_url += f"?{request.url.query}"
        
        # We can't easily return a RedirectResponse from a dependency 
        # that is expected to return a User unless we raise a custom exception 
        # or handle it in the route.
        # Let's raise an exception that we can catch or just redirect here if FastAPI allows.
        # Actually, raising an exception is better.
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            detail="Redirect to login",
            headers={"Location": f"/login?returnUrl={return_url}"}
        )
    return user


async def get_current_user_sse(
    request: Request,
    token: Optional[str] = Query(None, description="JWT token for SSE (since EventSource can't send headers)"),
) -> User:
    """
    Extract and validate current user from JWT token for SSE endpoints.

    EventSource API doesn't support custom headers, so we accept token via:
    1. Query parameter ?token=xxx (for SSE compatibility)
    2. access_token Cookie (Defense in Depth)
    3. Authorization header (fallback for fetch() calls)
    """
    # Try to get token from multiple sources
    effective_token = token or get_token_from_request(request)
    
    if not effective_token:
        logger.warning("SSE: No token found in query, cookie, or header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from app.services.user_database import get_user_db_service
    user_db = get_user_db_service()
    return await get_current_user_from_token(effective_token, user_db)


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
