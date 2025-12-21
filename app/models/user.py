"""
User model and authentication schemas.

Implements:
- User database model
- Password security (NIST SP 800-63B)
- Multi-tenant architecture
- Role-based access control (RBAC)

References:
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
- OWASP ASVS 2.1: Password Security
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, EmailStr, Field, validator


class UserRole(str, Enum):
    """User roles for RBAC."""

    ADMIN = "admin"  # Super-user: sees all resources, manages users
    USER = "user"  # Regular user: sees only own resources


class User(BaseModel):
    """
    User model for database storage.

    Multi-tenant architecture: each user owns their uploads.
    Admin can see all resources.

    User approval workflow:
    - New users start with is_approved=False
    - Admin must approve users before they can use the system
    - approved_by and approved_at track approval metadata
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    hashed_password: str
    role: UserRole = UserRole.USER
    is_active: bool = True
    is_approved: bool = False  # New: requires admin approval
    approved_by: Optional[str] = None  # User ID of approver
    approved_at: Optional[datetime] = None  # Timestamp of approval
    password_must_change: bool = False  # Force password change on first login
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None

    @validator("username")
    def username_alphanumeric(cls, v):
        """Username must be alphanumeric (+ underscore, hyphen)."""
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must be alphanumeric (a-z, 0-9, _, -)")
        return v.lower()

    class Config:
        orm_mode = True


class UserCreate(BaseModel):
    """Schema for user registration."""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)

    @validator("password")
    def password_strength(cls, v):
        """
        Password policy based on NIST SP 800-63B.

        Requirements:
        - Minimum 12 characters (NIST recommendation)
        - No complexity requirements (counter-productive per NIST)
        - Check against common passwords

        Note: We don't enforce special chars/uppercase because NIST says
        it doesn't improve security and leads to predictable patterns.
        """
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")

        # Check against common passwords
        common_passwords = [
            "password123456",
            "admin123456",
            "123456789012",
            "qwertyuiopas",
            "passwordpassword",
        ]
        if v.lower() in common_passwords:
            raise ValueError("Password is too common")

        return v


class UserResponse(BaseModel):
    """Schema for user API responses (no password!)."""

    id: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    is_approved: bool
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    password_must_change: bool = False
    created_at: datetime
    last_login: Optional[datetime]


class Token(BaseModel):
    """OAuth2 token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800  # 30 minutes
    password_must_change: bool = False  # Client must redirect to password change


class TokenData(BaseModel):
    """Data stored in JWT token."""

    sub: str  # Subject (user_id)
    username: str
    role: UserRole
    exp: datetime  # Expiration
