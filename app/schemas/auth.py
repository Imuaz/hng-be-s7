"""
Pydantic schemas for request/response validation.
"""

from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional
from uuid import UUID
import re


# User Schemas
class UserSignup(BaseModel):
    """Schema for user registration."""

    email: EmailStr = Field(
        ...,
        description="User's email address",
        examples=["user@example.com"],
        title="Email Address",
    )
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique username for the account",
        examples=["johndoe123"],
        title="Username",
    )
    password: str = Field(
        ...,
        min_length=8,
        description="Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character",
        examples=["StrongPass1!"],
        title="Password",
    )

    @field_validator("password")
    def validate_password(cls, value):
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one number")
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", value):
            raise ValueError("Password must contain at least one special character")
        return value


class UserLogin(BaseModel):
    """Schema for user login."""

    username: str = Field(
        ...,
        description="Registered username",
        examples=["johndoe123"],
        title="Username",
    )
    password: str = Field(
        ..., description="User's password", examples=["StrongPass1!"], title="Password"
    )


class UserResponse(BaseModel):
    """Schema for user data in responses."""

    id: UUID
    email: str
    username: str
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True


# Token Schemas
class Token(BaseModel):
    """Schema for JWT token response."""

    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Schema for decoded token data."""

    user_id: Optional[UUID] = None


class Logout(BaseModel):
    """Schema for user logout."""

    # No fields needed for a simple logout request,
    # as the token is typically sent in the header.
    pass


class ForgotPasswordRequest(BaseModel):
    """Schema for requesting a password reset."""

    email: EmailStr = Field(
        ...,
        description="Email address associated with the account",
        examples=["user@example.com"],
        title="Email Address",
    )


class ResetPasswordRequest(BaseModel):
    """Schema for resetting password with a token."""

    token: str = Field(
        ...,
        description="The password reset token received via email",
        examples=["9f85c15e..."],
        title="Reset Token",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        description="New password (must follow complexity rules)",
        examples=["NewStrongPass2@"],
        title="New Password",
    )

    @field_validator("new_password")
    def validate_password(cls, value):
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one number")
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", value):
            raise ValueError("Password must contain at least one special character")
        return value


# API Key Schemas
class APIKeyCreate(BaseModel):
    """Schema for creating an API key."""

    name: str = Field(..., min_length=1, max_length=100)
    expires_in_days: Optional[int] = Field(default=365, ge=1, le=3650)


class APIKeyResponse(BaseModel):
    """Schema for API key data in responses."""

    id: UUID
    key: str
    name: str
    created_at: datetime
    expires_at: datetime
    is_revoked: bool
    last_used_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class APIKeyListResponse(BaseModel):
    """Schema for listing API keys (without exposing the actual key)."""

    id: UUID
    name: str
    created_at: datetime
    expires_at: datetime
    is_revoked: bool
    last_used_at: Optional[datetime] = None

    class Config:
        from_attributes = True
