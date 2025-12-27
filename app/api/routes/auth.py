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
import os
import io
import base64
from pathlib import Path
from typing import List, Optional

import pyotp
import qrcode
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status, Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, validator
from zxcvbn import zxcvbn

from app.auth import create_access_token, get_current_admin_user, get_current_user
from app.models.user import (
    BulkActionResult,
    BulkUserActionRequest,
    BulkUserActionResponse,
    PaginatedUsersResponse,
    Token,
    User,
    UserCreate,
    UserResponse,
    UserRole,
)
from app.services.email_service import get_email_service
from app.services.user_database import get_user_db_service
from app.services.database import get_db_service
from app.services.password_reset_service import get_password_reset_service
from app.utils.config import get_data_dir
from app.utils.rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["auth"])


class PasswordUpdate(BaseModel):
    """Schema for password update (Issue #23: with zxcvbn strength validation)."""

    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=12, max_length=128)

    @validator("new_password")
    def password_strength(cls, v):
        """
        Enhanced password policy (Issue #23: NIST SP 800-63B + zxcvbn strength meter).

        Requirements:
        - Minimum 12 characters (NIST recommendation)
        - Strength score ≥ 3/4 (zxcvbn: strong or very strong)
        - Detailed feedback on weak passwords
        """
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")

        # Check password strength using zxcvbn (0-4 scale)
        result = zxcvbn(v)
        score = result['score']
        feedback = result['feedback']

        # Require score ≥ 3 (strong or very strong)
        if score < 3:
            # Build detailed error message from zxcvbn feedback
            error_parts = [f"Password is too weak (strength: {score}/4, need ≥3)"]

            if feedback.get('warning'):
                error_parts.append(f"Warning: {feedback['warning']}")

            if feedback.get('suggestions'):
                suggestions = '; '.join(feedback['suggestions'])
                error_parts.append(f"Suggestions: {suggestions}")

            raise ValueError('. '.join(error_parts))

        return v


class ForgotPasswordRequest(BaseModel):
    """Schema for password reset request."""
    email: EmailStr


@router.post("/auth/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    email_service=Depends(get_email_service),
):
    """
    Request a password reset link.
    
    Rate limited: 3 requests per 15 minutes per IP.
    Always returns 200 OK to prevent user enumeration.
    """
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    rate_limiter = get_rate_limiter()
    
    # Custom limit for forgot password: 3 attempts
    # We reuse the rate limiter but check manually if needed or just use the generic one.
    # The generic one has exponential backoff after 3 failed attempts.
    # Here we want strict limit on requests regardless of success/failure to prevent spam.
    
    # NOTE: The current RateLimiter is designed for failed LOGIN attempts with exponential backoff.
    # We'll use a simple check here: if is_allowed returns False, we reject.
    # Ideally we'd have a separate limiter for this endpoint.
    # For now, we reuse it.
    
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many requests. Please try again in {retry_after:.0f} seconds.",
        )
        
    # We record "failure" to increment the counter for this IP, effectively rate limiting it.
    # This is a bit of a hack on the existing RateLimiter designed for logins.
    # A better approach would be a separate RateLimiter instance or method.
    # But sticking to constraints:
    rate_limiter.record_failure(client_ip) 
    
    user_db = get_user_db_service()
    
    # Lookup user (case-insensitive done in DB service usually, but email is lowercased there)
    # We need to get user by email.
    # Existing method is get_user_by_username.
    # We need get_user_by_email.
    
    # Let's add get_user_by_email to UserDatabaseService or iterate/query manually?
    # UserDatabaseService has no get_user_by_email explicitly shown in previous read_file output?
    # Wait, let's check `app/services/user_database.py` again.
    # It has `get_user_by_username`.
    # It has `get_user_by_id`.
    # It does NOT have `get_user_by_email`.
    
    # I will query directly using the pool here or I should add it to service.
    # Best practice: Add to service. But I can't edit that file in this step easily without context switching.
    # I will use a direct query via pool for now or fetch all and filter (bad performance).
    # Actually, `create_user` checks for email existence, so index exists.
    
    # For now, I'll implement a quick lookup helper here or use what's available.
    # I'll rely on `user_db.pool.fetch_one`.
    
    query, params = user_db.pool.translate_query(
        "SELECT id FROM users WHERE email = ?",
        (payload.email.lower(),)
    )
    row = await user_db.pool.fetch_one(query, *params)
    
    if row:
        user_id = str(row["id"])
        user = await user_db.get_user_by_id(user_id)
        
        if user and user.is_active and user.is_approved:
            # Generate token
            reset_service = get_password_reset_service()
            token = await reset_service.create_reset_token(
                user_id=user.id,
                ip_address=client_ip,
                user_agent=request.headers.get("User-Agent")
            )
            
            # Construct reset link
            # Assuming frontend URL structure
            base_url = os.getenv("APP_BASE_URL", "http://pcaplab.com")
            reset_link = f"{base_url}/reset-password?token={token}"
            
            # Send email
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            background_tasks.add_task(
                email_service.send_password_reset_request_email,
                user,
                reset_link,
                client_ip,
                timestamp
            )
            
            logger.info(f"Password reset requested for {user.email}")
        else:
            logger.warning(f"Password reset requested for inactive/unapproved user {payload.email}")
    else:
        logger.warning(f"Password reset requested for non-existent email {payload.email}")
        
    # Always return 200 OK
    return {"message": "If an account exists with this email, a password reset link has been sent."}


class ResetPasswordRequest(BaseModel):
    """Schema for resetting password with token."""
    token: str
    new_password: str = Field(..., min_length=12, max_length=128)

    @validator("new_password")
    def password_strength(cls, v):
        """Validate password strength (zxcvbn)."""
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")

        result = zxcvbn(v)
        score = result['score']
        feedback = result['feedback']

        if score < 3:
            error_parts = [f"Password is too weak (strength: {score}/4, need ≥3)"]
            if feedback.get('warning'):
                error_parts.append(f"Warning: {feedback['warning']}")
            raise ValueError('. '.join(error_parts))
        return v


@router.post("/auth/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    background_tasks: BackgroundTasks,
    email_service=Depends(get_email_service),
):
    """
    Reset password using a valid token.
    """
    reset_service = get_password_reset_service()
    
    # 1. Hash token provided by user
    import hashlib
    token_hash = hashlib.sha256(payload.token.encode('utf-8')).hexdigest()
    
    # 2. Validate token
    user = await reset_service.validate_token(token_hash)
    if not user:
        # Generic error message for security? 
        # Actually, for reset, if token is invalid, we should tell them so they can request a new one.
        # But we shouldn't reveal if the token was "just expired" vs "never existed" if we want to be super strict,
        # but UX wise, "Invalid or expired token" is standard.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token. Please request a new password reset link.",
        )
    
    user_db = get_user_db_service()
    
    # 3. Check password history (reuse)
    try:
        is_reused = await user_db.check_password_reuse(user.id, payload.new_password)
        if is_reused:
            raise ValueError("Password was used recently. Please choose a different password (last 5 passwords cannot be reused)")
            
        # 4. Update password
        # Use update_password which handles hashing and history update
        # This also clears password_must_change flag
        await user_db.update_password(user.id, payload.new_password)
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error resetting password for user {user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
        
    # 5. Consume token
    await reset_service.consume_token(token_hash)
    
    # 6. Invalidate other tokens for this user?
    # Security best practice: invalidate all other reset tokens
    await reset_service.invalidate_user_tokens(user.id)
    
    # 7. Send confirmation email
    client_ip = request.client.host if request.client else "unknown"
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    background_tasks.add_task(
        email_service.send_password_reset_success_email,
        user,
        client_ip,
        timestamp
    )
    
    logger.info(f"Password reset successful for user {user.username}")
    
    return {"message": "Password reset successful. You can now login with your new password."}


@router.post("/token", response_model=Token)
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    totp_code: Optional[str] = Form(None)
):
    """
    Login endpoint (OAuth2 password flow) with rate limiting.
    
    Now sets an HttpOnly cookie for session-like access to HTML pages.

    Args:
        request: HTTP request (for IP-based rate limiting)
        form_data: OAuth2 form with username and password
        totp_code: Optional 2FA code (required if 2FA enabled)

    Returns:
        Access token (JWT)

    Raises:
        HTTPException 401: If credentials are invalid
        HTTPException 403: If account is not approved
        HTTPException 429: If rate limit exceeded

    Security:
        - Rate limiting: Exponential backoff after failed attempts (OWASP ASVS V2.2.1)
        - Username enumeration prevention: Generic error messages (CWE-204)

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
    # Get client IP for rate limiting
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting check (OWASP ASVS V2.2.1)
    rate_limiter = get_rate_limiter()
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {retry_after:.0f} seconds.",
            headers={"Retry-After": str(int(retry_after))},
        )

    user_db = get_user_db_service()

    # Get user by username first
    user = await user_db.get_user_by_username(form_data.username)

    # Security: All failed login scenarios use generic logging to prevent username enumeration
    # (OWASP ASVS V2.2.2, CWE-204 mitigation)
    if not user:
        # User doesn't exist - return generic error (prevent username enumeration)
        logger.warning("Failed login attempt: invalid credentials")
        rate_limiter.record_failure(client_ip)  # Track failed attempt
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if account is active
    if not user.is_active:
        logger.warning("Failed login attempt: account inactive")
        rate_limiter.record_failure(client_ip)  # Track failed attempt
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated. Contact administrator.",
        )

    # Check if account is approved
    if not user.is_approved:
        logger.info("Failed login attempt: account pending approval")
        rate_limiter.record_failure(client_ip)  # Track failed attempt
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account pending approval. Please wait for administrator approval.",
        )

    # Verify password
    if not user_db.verify_password(form_data.password, user.hashed_password):
        logger.warning("Failed login attempt: invalid credentials")
        rate_limiter.record_failure(client_ip)  # Track failed attempt
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check 2FA (Two-Factor Authentication)
    if user.is_2fa_enabled:
        if not totp_code:
            # Indicate MFA required
            # We return 401 but with a specific detail or header so the frontend knows to prompt for code
            logger.info(f"2FA required for user {user.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Two-factor authentication required",
                headers={"WWW-Authenticate": "Bearer", "X-MFA-Required": "true"},
            )
        
        # Verify TOTP
        if not user.totp_secret:
             logger.error(f"User {user.username} has 2FA enabled but no secret")
             raise HTTPException(status_code=500, detail="Internal 2FA error")

        totp = pyotp.TOTP(user.totp_secret)
        # Allow window of 1 (30s before/after) to account for clock drift
        if not totp.verify(totp_code, valid_window=1):
            # Try backup codes
            is_valid_backup = await user_db.consume_backup_code(user.id, totp_code)
            
            if not is_valid_backup:
                logger.warning("Failed login attempt: invalid 2FA code")
                rate_limiter.record_failure(client_ip)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid 2FA code",
                    headers={"WWW-Authenticate": "Bearer"},
                )

    # Success - reset rate limiter
    rate_limiter.record_success(client_ip)

    # Update last login
    await user_db.update_last_login(user.id)

    # Create access token
    access_token = create_access_token(user)

    # Set cookie for HTML page access (Defense in Depth)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        max_age=1800,  # 30 minutes, same as JWT expiry
    )

    logger.info(f"User logged in: {user.username} (role: {user.role.value}, password_must_change: {user.password_must_change})")

    return Token(access_token=access_token, token_type="bearer", expires_in=1800, password_must_change=user.password_must_change)


@router.post("/logout")
async def logout(response: Response):
    """
    Logout endpoint.
    Clears the access_token cookie.
    """
    response.delete_cookie(
        key="access_token",
        httponly=True,
        samesite="lax",
    )
    return {"message": "Logged out successfully"}


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    background_tasks: BackgroundTasks,
    email_service=Depends(get_email_service),
):
    """
    User registration endpoint.

    Args:
        user_data: User registration data (username, email, password)
        background_tasks: FastAPI background tasks
        email_service: Email service dependency

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

        # Send registration confirmation email
        background_tasks.add_task(email_service.send_registration_email, user)

        # Return user without password
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            is_approved=user.is_approved,
            approved_by=user.approved_by,
            approved_at=user.approved_at,
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
        is_approved=current_user.is_approved,
        approved_by=current_user.approved_by,
        approved_at=current_user.approved_at,
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

    # Update password in database (includes history check - Issue #23)
    try:
        await user_db.update_password(current_user.id, password_update.new_password)
    except ValueError as e:
        # Password reuse detected (last 5 passwords)
        logger.warning(f"Password update failed for {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    logger.info(f"Password updated for user: {current_user.username}")
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        is_approved=current_user.is_approved,
        approved_by=current_user.approved_by,
        approved_at=current_user.approved_at,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
    )


@router.get("/users", response_model=list[UserResponse] | PaginatedUsersResponse)
async def get_all_users(
    admin: User = Depends(get_current_admin_user),
    limit: int = 100,
    offset: Optional[int] = None,
    status: Optional[str] = None,
    role: Optional[str] = None,
):
    """
    Get all users (admin only).

    Args:
        admin: Current admin user
        limit: Maximum users to return (default: 100)
        offset: Number of users to skip (if provided, returns PaginatedUsersResponse)
        status: Filter by status (pending, approved, blocked)
        role: Filter by role (admin, user)

    Returns:
        List of users (legacy) or PaginatedUsersResponse (if offset provided)

    Requires:
        Admin role
    """
    user_db = get_user_db_service()
    
    # If offset is None, we assume legacy behavior (list only)
    # But UserDatabaseService now returns a tuple, so we handle both
    effective_offset = offset if offset is not None else 0
    
    users, total = await user_db.get_all_users(
        limit=limit, 
        offset=effective_offset,
        status_filter=status,
        role_filter=role
    )

    logger.info(f"Admin {admin.username} fetched {len(users)} users (Total: {total}, Offset: {effective_offset})")

    # Map to UserResponse
    user_responses = [
        UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            is_approved=user.is_approved,
            approved_by=user.approved_by,
            approved_at=user.approved_at,
            created_at=user.created_at,
            last_login=user.last_login,
        )
        for user in users
    ]

    # Backward compatibility: if offset was NOT provided in query, return plain list
    if offset is None:
        return user_responses

    # Otherwise return paginated wrapper
    return PaginatedUsersResponse(
        users=user_responses,
        total=total,
        offset=effective_offset,
        limit=limit
    )


@router.put("/admin/users/{user_id}/approve", response_model=UserResponse)
async def approve_user(
    user_id: str,
    background_tasks: BackgroundTasks,
    admin: User = Depends(get_current_admin_user),
    email_service=Depends(get_email_service),
):
    """
    Approve a user account (admin only).

    Args:
        user_id: User ID to approve
        background_tasks: FastAPI background tasks
        admin: Current admin user (from JWT token)
        email_service: Email service dependency

    Returns:
        Updated user info

    Raises:
        HTTPException 404: If user not found
        HTTPException 400: If user is already approved

    Requires:
        Admin role

    Usage (JavaScript):
        const token = localStorage.getItem('access_token');
        const response = await fetch(`/api/admin/users/${userId}/approve`, {
            method: 'PUT',
            headers: {'Authorization': `Bearer ${token}`}
        });
        const updatedUser = await response.json();
    """
    user_db = get_user_db_service()

    # Get user to approve
    user = await user_db.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    if user.is_approved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User {user.username} is already approved",
        )

    # Approve user
    success = await user_db.approve_user(user_id, admin.id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve user",
        )

    # Fetch updated user
    updated_user = await user_db.get_user_by_id(user_id)

    logger.warning(f"🔓 AUDIT: Admin {admin.username} approved user {user.username} (id: {user_id})")

    # Send approval notification email
    background_tasks.add_task(email_service.send_approval_email, updated_user, admin.username)

    return UserResponse(
        id=updated_user.id,
        username=updated_user.username,
        email=updated_user.email,
        role=updated_user.role,
        is_active=updated_user.is_active,
        is_approved=updated_user.is_approved,
        approved_by=updated_user.approved_by,
        approved_at=updated_user.approved_at,
        created_at=updated_user.created_at,
        last_login=updated_user.last_login,
    )


@router.put("/admin/users/{user_id}/block", response_model=UserResponse)
async def block_user(
    user_id: str,
    admin: User = Depends(get_current_admin_user),
):
    """
    Block a user account (admin only).

    Sets is_active=False, preventing login.

    Args:
        user_id: User ID to block
        admin: Current admin user (from JWT token)

    Returns:
        Updated user info

    Raises:
        HTTPException 404: If user not found
        HTTPException 400: If trying to block self or another admin
        HTTPException 400: If user is already blocked

    Requires:
        Admin role

    Usage (JavaScript):
        const token = localStorage.getItem('access_token');
        const response = await fetch(`/api/admin/users/${userId}/block`, {
            method: 'PUT',
            headers: {'Authorization': `Bearer ${token}`}
        });
        const updatedUser = await response.json();
    """
    user_db = get_user_db_service()

    # Get user to block
    user = await user_db.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    # Prevent self-blocking
    if user.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot block your own account",
        )

    # Prevent blocking other admins
    if user.role == UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot block admin accounts. Contact system administrator.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User {user.username} is already blocked",
        )

    # Block user (set is_active=False)
    success = await user_db.block_user(user_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to block user",
        )

    # Fetch updated user
    updated_user = await user_db.get_user_by_id(user_id)

    logger.warning(f"🔒 AUDIT: Admin {admin.username} blocked user {user.username} (id: {user_id})")

    return UserResponse(
        id=updated_user.id,
        username=updated_user.username,
        email=updated_user.email,
        role=updated_user.role,
        is_active=updated_user.is_active,
        is_approved=updated_user.is_approved,
        approved_by=updated_user.approved_by,
        approved_at=updated_user.approved_at,
        created_at=updated_user.created_at,
        last_login=updated_user.last_login,
    )


@router.put("/admin/users/{user_id}/unblock", response_model=UserResponse)
async def unblock_user(
    user_id: str,
    admin: User = Depends(get_current_admin_user),
):
    """
    Unblock a user account (admin only).

    Sets is_active=True, allowing login again.

    Args:
        user_id: User ID to unblock
        admin: Current admin user (from JWT token)

    Returns:
        Updated user info

    Raises:
        HTTPException 404: If user not found
        HTTPException 400: If user is already active

    Requires:
        Admin role

    Usage (JavaScript):
        const token = localStorage.getItem('access_token');
        const response = await fetch(`/api/admin/users/${userId}/unblock`, {
            method: 'PUT',
            headers: {'Authorization': `Bearer ${token}`}
        });
        const updatedUser = await response.json();
    """
    user_db = get_user_db_service()

    # Get user to unblock
    user = await user_db.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User {user.username} is already active",
        )

    # Unblock user (set is_active=True)
    success = await user_db.unblock_user(user_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unblock user",
        )

    # Fetch updated user
    updated_user = await user_db.get_user_by_id(user_id)

    logger.warning(f"🔓 AUDIT: Admin {admin.username} unblocked user {user.username} (id: {user_id})")

    return UserResponse(
        id=updated_user.id,
        username=updated_user.username,
        email=updated_user.email,
        role=updated_user.role,
        is_active=updated_user.is_active,
        is_approved=updated_user.is_approved,
        approved_by=updated_user.approved_by,
        approved_at=updated_user.approved_at,
        created_at=updated_user.created_at,
        last_login=updated_user.last_login,
    )


@router.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: User = Depends(get_current_admin_user),
):
    """
    Delete a user account (admin only).

    Deletes the user and all associated tasks (CASCADE).

    Args:
        user_id: User ID to delete
        admin: Current admin user (from JWT token)

    Returns:
        Success message

    Raises:
        HTTPException 404: If user not found
        HTTPException 400: If trying to delete self or another admin

    Requires:
        Admin role

    Usage (JavaScript):
        const token = localStorage.getItem('access_token');
        const response = await fetch(`/api/admin/users/${userId}`, {
            method: 'DELETE',
            headers: {'Authorization': `Bearer ${token}`}
        });
        const result = await response.json();
    """
    user_db = get_user_db_service()

    # Get user to delete
    user = await user_db.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    # Prevent self-deletion
    if user.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    # Prevent deleting other admins
    if user.role == UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete admin accounts. Contact system administrator.",
        )

    # NEW: Get all tasks for this user to delete associated files
    db_service = get_db_service()
    user_tasks = await db_service.get_recent_tasks(limit=10000, owner_id=user_id)

    # NEW: Delete physical files before deleting database records
    data_dir = get_data_dir()
    uploads_dir = data_dir / "uploads"
    reports_dir = data_dir / "reports"

    files_deleted = {"uploads": 0, "reports": 0}
    deletion_errors = []

    for task in user_tasks:
        task_id = task.task_id

        # Delete PCAP file (multiple extensions possible)
        pcap_files = list(uploads_dir.glob(f"{task_id}.*"))
        for pcap_file in pcap_files:
            try:
                if pcap_file.exists():
                    pcap_file.unlink()
                    files_deleted["uploads"] += 1
                    logger.info(f"Deleted PCAP for user {user.username}: {pcap_file.name}")
            except Exception as e:
                deletion_errors.append(f"Failed to delete {pcap_file.name}: {str(e)}")
                logger.error(f"Error deleting PCAP {pcap_file}: {e}")

        # Delete HTML and JSON reports
        for ext in ["html", "json"]:
            report_file = reports_dir / f"{task_id}.{ext}"
            try:
                if report_file.exists():
                    report_file.unlink()
                    files_deleted["reports"] += 1
                    logger.info(f"Deleted report for user {user.username}: {report_file.name}")
            except Exception as e:
                deletion_errors.append(f"Failed to delete {report_file.name}: {str(e)}")
                logger.error(f"Error deleting report {report_file}: {e}")

    # Delete user (CASCADE will delete associated database records: tasks, progress, etc.)
    try:
        # Execute DELETE query
        query, params = user_db.pool.translate_query(
            "DELETE FROM users WHERE id = ?",
            (user_id,),
        )
        await user_db.pool.execute(query, *params)

        logger.warning(
            f"🗑️  AUDIT: Admin {admin.username} deleted user {user.username} (id: {user_id}). "
            f"Files removed: {files_deleted['uploads']} uploads, {files_deleted['reports']} reports."
        )

        return {
            "message": f"User {user.username} deleted successfully",
            "user_id": user_id,
            "username": user.username,
            "files_deleted": files_deleted,
            "errors": deletion_errors if deletion_errors else None
        }

    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {str(e)}",
        )


class AdminUserCreate(BaseModel):
    """Schema for admin user creation with temporary password."""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: UserRole = UserRole.USER


@router.post("/admin/users", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_user_by_admin(
    user_data: AdminUserCreate,
    admin: User = Depends(get_current_admin_user),
):
    """
    Create a new user with a temporary password (admin only).

    The user will be forced to change their password on first login.
    A random temporary password is generated and returned in the response.

    Args:
        username: Username (3-50 chars, alphanumeric)
        email: User email address
        role: User role (default: user)
        admin: Current admin user (from JWT token)

    Returns:
        User info + temporary password (SAVE THIS PASSWORD!)

    Raises:
        HTTPException 400: If username/email already exists
        HTTPException 403: If not admin
        HTTPException 500: Database error

    Security:
        - Password is 16 characters, URL-safe random
        - User is auto-approved
        - password_must_change flag is set to True
        - Password is returned ONCE in response (not stored)

    Example Response:
        {
            "user": {
                "id": "...",
                "username": "john.doe",
                "email": "john@example.com",
                "role": "user",
                "is_approved": true,
                "password_must_change": true
            },
            "temporary_password": "Xy9K-vBm2LpQ4nRt",
            "message": "User created. Temporary password must be changed on first login."
        }
    """
    import secrets

    user_db = get_user_db_service()

    # Generate secure temporary password (16 chars, URL-safe)
    temporary_password = secrets.token_urlsafe(16)[:16]

    # Create user creation payload
    user_create = UserCreate(
        username=user_data.username,
        email=user_data.email,
        password=temporary_password,
    )

    try:
        # Create user with password_must_change=True and auto_approve=True
        user = await user_db.create_user(
            user_create,
            role=user_data.role,
            auto_approve=True,
            password_must_change=True,
        )

        logger.warning(
            f"🔐 ADMIN ACTION: User {user_data.username} created by admin {admin.username} "
            f"with temporary password (must change on first login)"
        )

        return {
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "is_active": user.is_active,
                "is_approved": user.is_approved,
                "password_must_change": user.password_must_change,
                "created_at": user.created_at.isoformat(),
            },
            "temporary_password": temporary_password,
            "message": "✅ User created successfully. Temporary password must be changed on first login.",
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}",
        )


@router.post("/admin/users/bulk/approve", response_model=BulkUserActionResponse)
async def bulk_approve_users(
    request: BulkUserActionRequest,
    background_tasks: BackgroundTasks,
    admin: User = Depends(get_current_admin_user),
    email_service=Depends(get_email_service),
):
    """
    Bulk approve multiple user accounts (admin only).

    Approves multiple users in a single request. Users that are already approved
    or don't exist will be marked as failed in the response.

    Args:
        request: List of user IDs to approve
        background_tasks: FastAPI background tasks
        admin: Current admin user (from JWT token)
        email_service: Email service dependency

    Returns:
        Summary of bulk operation (success count, failed count, detailed results)

    Requires:
        Admin role

    Example Request:
        POST /api/admin/users/bulk/approve
        {
            "user_ids": [
                "550e8400-e29b-41d4-a716-446655440000",
                "660e8400-e29b-41d4-a716-446655440001"
            ]
        }

    Example Response:
        {
            "total": 2,
            "success": 1,
            "failed": 1,
            "results": [
                {
                    "user_id": "550e8400-e29b-41d4-a716-446655440000",
                    "username": "alice",
                    "status": "success"
                },
                {
                    "user_id": "660e8400-e29b-41d4-a716-446655440001",
                    "username": "bob",
                    "status": "failed",
                    "reason": "User is already approved"
                }
            ]
        }
    """
    user_db = get_user_db_service()
    results = []
    success_count = 0
    failed_count = 0

    for user_id in request.user_ids:
        try:
            # Get user
            user = await user_db.get_user_by_id(user_id)

            if not user:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        status="failed",
                        reason="User not found",
                    )
                )
                failed_count += 1
                continue

            # Check if already approved
            if user.is_approved:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        username=user.username,
                        status="failed",
                        reason="User is already approved",
                    )
                )
                failed_count += 1
                continue

            # Approve user
            approval_success = await user_db.approve_user(user_id, admin.id)

            if not approval_success:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        username=user.username,
                        status="failed",
                        reason="Failed to approve user (database error)",
                    )
                )
                failed_count += 1
                continue

            # Success
            results.append(
                BulkActionResult(
                    user_id=user_id,
                    username=user.username,
                    status="success",
                )
            )
            success_count += 1

            # Send approval notification email
            background_tasks.add_task(email_service.send_approval_email, user, admin.username)

            # Audit log
            logger.warning(f"🔓 AUDIT: Admin {admin.username} approved user {user.username} (id: {user_id}) [BULK]")

        except Exception as e:
            logger.error(f"Error approving user {user_id}: {e}")
            results.append(
                BulkActionResult(
                    user_id=user_id,
                    status="failed",
                    reason=f"Internal error: {str(e)}",
                )
            )
            failed_count += 1

    return BulkUserActionResponse(
        total=len(request.user_ids),
        success=success_count,
        failed=failed_count,
        results=results,
    )


@router.post("/admin/users/bulk/block", response_model=BulkUserActionResponse)
async def bulk_block_users(
    request: BulkUserActionRequest,
    admin: User = Depends(get_current_admin_user),
):
    """
    Bulk block multiple user accounts (admin only).

    Blocks multiple users in a single request. Sets is_active=False for each user.

    Args:
        request: List of user IDs to block
        admin: Current admin user (from JWT token)

    Returns:
        Summary of bulk operation (success count, failed count, detailed results)

    Safety Features:
        - Cannot block your own account
        - Cannot block other admin accounts
        - Skips users that are already blocked

    Requires:
        Admin role

    Example Request:
        POST /api/admin/users/bulk/block
        {
            "user_ids": [
                "550e8400-e29b-41d4-a716-446655440000",
                "660e8400-e29b-41d4-a716-446655440001"
            ]
        }

    Example Response:
        {
            "total": 2,
            "success": 2,
            "failed": 0,
            "results": [
                {
                    "user_id": "550e8400-e29b-41d4-a716-446655440000",
                    "username": "alice",
                    "status": "success"
                },
                {
                    "user_id": "660e8400-e29b-41d4-a716-446655440001",
                    "username": "bob",
                    "status": "success"
                }
            ]
        }
    """
    user_db = get_user_db_service()
    results = []
    success_count = 0
    failed_count = 0

    for user_id in request.user_ids:
        try:
            # Get user
            user = await user_db.get_user_by_id(user_id)

            if not user:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        status="failed",
                        reason="User not found",
                    )
                )
                failed_count += 1
                continue

            # Prevent self-blocking
            if user.id == admin.id:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        username=user.username,
                        status="failed",
                        reason="Cannot block your own account",
                    )
                )
                failed_count += 1
                continue

            # Prevent blocking other admins
            if user.role == UserRole.ADMIN:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        username=user.username,
                        status="failed",
                        reason="Cannot block admin accounts",
                    )
                )
                failed_count += 1
                continue

            # Check if already blocked
            if not user.is_active:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        username=user.username,
                        status="failed",
                        reason="User is already blocked",
                    )
                )
                failed_count += 1
                continue

            # Block user
            block_success = await user_db.block_user(user_id)

            if not block_success:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        username=user.username,
                        status="failed",
                        reason="Failed to block user (database error)",
                    )
                )
                failed_count += 1
                continue

            # Success
            results.append(
                BulkActionResult(
                    user_id=user_id,
                    username=user.username,
                    status="success",
                )
            )
            success_count += 1

            # Audit log
            logger.warning(f"🔒 AUDIT: Admin {admin.username} blocked user {user.username} (id: {user_id}) [BULK]")

        except Exception as e:
            logger.error(f"Error blocking user {user_id}: {e}")
            results.append(
                BulkActionResult(
                    user_id=user_id,
                    status="failed",
                    reason=f"Internal error: {str(e)}",
                )
            )
            failed_count += 1

    return BulkUserActionResponse(
        total=len(request.user_ids),
        success=success_count,
        failed=failed_count,
        results=results,
    )


@router.post("/admin/users/bulk/unblock", response_model=BulkUserActionResponse)
async def bulk_unblock_users(
    request: BulkUserActionRequest,
    admin: User = Depends(get_current_admin_user),
):
    """
    Bulk unblock multiple user accounts (admin only).

    Unblocks multiple users in a single request. Sets is_active=True for each user.

    Args:
        request: List of user IDs to unblock
        admin: Current admin user (from JWT token)

    Returns:
        Summary of bulk operation (success count, failed count, detailed results)

    Requires:
        Admin role

    Example Request:
        POST /api/admin/users/bulk/unblock
        {
            "user_ids": [
                "550e8400-e29b-41d4-a716-446655440000",
                "660e8400-e29b-41d4-a716-446655440001"
            ]
        }

    Example Response:
        {
            "total": 2,
            "success": 1,
            "failed": 1,
            "results": [
                {
                    "user_id": "550e8400-e29b-41d4-a716-446655440000",
                    "username": "alice",
                    "status": "success"
                },
                {
                    "user_id": "660e8400-e29b-41d4-a716-446655440001",
                    "username": "bob",
                    "status": "failed",
                    "reason": "User is already active"
                }
            ]
        }
    """
    user_db = get_user_db_service()
    results = []
    success_count = 0
    failed_count = 0

    for user_id in request.user_ids:
        try:
            # Get user
            user = await user_db.get_user_by_id(user_id)

            if not user:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        status="failed",
                        reason="User not found",
                    )
                )
                failed_count += 1
                continue

            # Check if already active
            if user.is_active:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        username=user.username,
                        status="failed",
                        reason="User is already active",
                    )
                )
                failed_count += 1
                continue

            # Unblock user
            unblock_success = await user_db.unblock_user(user_id)

            if not unblock_success:
                results.append(
                    BulkActionResult(
                        user_id=user_id,
                        username=user.username,
                        status="failed",
                        reason="Failed to unblock user (database error)",
                    )
                )
                failed_count += 1
                continue

            # Success
            results.append(
                BulkActionResult(
                    user_id=user_id,
                    username=user.username,
                    status="success",
                )
            )
            success_count += 1

            # Audit log
            logger.warning(f"🔓 AUDIT: Admin {admin.username} unblocked user {user.username} (id: {user_id}) [BULK]")

        except Exception as e:
            logger.error(f"Error unblocking user {user_id}: {e}")
            results.append(
                BulkActionResult(
                    user_id=user_id,
                    status="failed",
                    reason=f"Internal error: {str(e)}",
                )
            )
            failed_count += 1

    return BulkUserActionResponse(
        total=len(request.user_ids),
        success=success_count,
        failed=failed_count,
        results=results,
    )


# ========================================
# 2FA ENDPOINTS
# ========================================

class TwoFASetupResponse(BaseModel):
    """Response for 2FA setup initiation."""
    secret: str
    qr_code: str

class TwoFAEnableRequest(BaseModel):
    """Request to enable 2FA."""
    secret: str
    code: str

class TwoFADisableRequest(BaseModel):
    """Request to disable 2FA."""
    password: str

@router.post("/users/me/2fa/setup", response_model=TwoFASetupResponse)
async def setup_2fa(current_user: User = Depends(get_current_user)):
    """
    Initiate 2FA setup.
    Generates a secret and QR code.
    Does NOT enable 2FA yet (user must verify).
    
    Returns:
        Secret key and QR code image (base64)
    """
    if current_user.is_2fa_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
        
    # Generate secret
    secret = pyotp.random_base32()
    
    # Create provisioning URI
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name="PCAP Analyzer"
    )
    
    # Generate QR code
    img = qrcode.make(uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return TwoFASetupResponse(
        secret=secret,
        qr_code=f"data:image/png;base64,{qr_b64}"
    )

@router.post("/users/me/2fa/enable")
async def enable_2fa(
    request: TwoFAEnableRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Enable 2FA after setup.
    Verifies the code against the secret.
    Returns backup codes.
    
    Returns:
        Backup codes (save these!)
    """
    if current_user.is_2fa_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
        
    # Verify code
    totp = pyotp.TOTP(request.secret)
    # Allow window of 1 (30s before/after)
    if not totp.verify(request.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid 2FA code")
        
    # Generate backup codes (10 codes, 8 hex chars each)
    import secrets
    backup_codes = [secrets.token_hex(4) for _ in range(10)]
    
    user_db = get_user_db_service()
    await user_db.enable_2fa(current_user.id, request.secret, backup_codes)
    
    logger.info(f"2FA enabled for user {current_user.username}")
    
    return {"message": "2FA enabled successfully", "backup_codes": backup_codes}

@router.post("/users/me/2fa/disable")
async def disable_2fa(
    request: TwoFADisableRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Disable 2FA.
    Requires password for security.
    """
    if not current_user.is_2fa_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled")
        
    user_db = get_user_db_service()
    
    # Verify password
    if not user_db.verify_password(request.password, current_user.hashed_password):
        logger.warning(f"Failed to disable 2FA for {current_user.username}: incorrect password")
        raise HTTPException(status_code=401, detail="Incorrect password")
        
    await user_db.disable_2fa(current_user.id)
    
    logger.info(f"2FA disabled for user {current_user.username}")
    
    return {"message": "2FA disabled successfully"}
