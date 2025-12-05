"""
Authentication service layer.
Business logic for user authentication and JWT token management.
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from datetime import timedelta
from app.models.auth import User
from app.schemas.auth import UserSignup, UserLogin
from app.utils.security import get_password_hash, verify_password, create_access_token
from app.config import settings


def create_user(db: Session, user_data: UserSignup) -> User:
    """
    Create a new user in the database.

    Args:
        db: Database session
        user_data: User signup data

    Returns:
        Created user object

    Raises:
        HTTPException: If email or username already exists
    """
    # Check if email already exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    # Check if username already exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken"
        )

    # Hash password and create user
    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hashed_password,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


def authenticate_user(db: Session, username: str, password: str) -> User:
    """
    Authenticate a user with username and password.

    Args:
        db: Database session
        username: User's username
        password: Plain text password

    Returns:
        Authenticated user object

    Raises:
        HTTPException: If credentials are invalid
    """
    user = db.query(User).filter(User.username == username).first()

    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user account"
        )

    return user


def create_user_token(user: User) -> str:
    """
    Create a JWT access token for a user.

    Args:
        user: User object

    Returns:
        JWT access token string
    """
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id}, expires_delta=access_token_expires
    )
    return access_token
