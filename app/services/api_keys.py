"""
API Key service layer.
Business logic for API key generation, validation, and management.
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from datetime import datetime, timedelta
from typing import List, Optional
from app.models.auth import APIKey
from app.utils.security import generate_api_key
from app.config import settings


def create_api_key(
    db: Session, user_id: int, name: str, expires_in_days: int = None
) -> APIKey:
    """
    Create a new API key for a user.

    Args:
        db: Database session
        user_id: ID of the user creating the API key
        name: Name/description of the API key
        expires_in_days: Number of days until expiration

    Returns:
        Created API key object
    """
    if expires_in_days is None:
        expires_in_days = settings.API_KEY_EXPIRE_DAYS

    # Generate unique API key
    key = generate_api_key()

    # Calculate expiration date
    expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    # Create API key record
    db_api_key = APIKey(key=key, name=name, user_id=user_id, expires_at=expires_at)

    db.add(db_api_key)
    db.commit()
    db.refresh(db_api_key)

    return db_api_key


def validate_api_key(db: Session, key: str) -> Optional[dict]:
    """
    Validate an API key and update its last_used_at timestamp.

    Args:
        db: Database session
        key: API key string to validate

    Returns:
        Dictionary with API key info or None if invalid

    Raises:
        HTTPException: If API key is expired
    """
    api_key = (
        db.query(APIKey).filter(APIKey.key == key, APIKey.is_revoked == False).first()
    )

    if not api_key:
        return None

    # Check if expired
    if api_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="API key has expired"
        )

    # Update last used timestamp
    api_key.last_used_at = datetime.utcnow()
    db.commit()

    return {
        "api_key_id": api_key.id,
        "user_id": api_key.user_id,
        "name": api_key.name,
        "type": "service",
    }


def list_user_api_keys(db: Session, user_id: int) -> List[APIKey]:
    """
    Get all API keys for a user.

    Args:
        db: Database session
        user_id: ID of the user

    Returns:
        List of API key objects
    """
    return db.query(APIKey).filter(APIKey.user_id == user_id).all()


def revoke_api_key(db: Session, key_id: int, user_id: int) -> APIKey:
    """
    Revoke an API key.

    Args:
        db: Database session
        key_id: ID of the API key to revoke
        user_id: ID of the user (for authorization check)

    Returns:
        Revoked API key object

    Raises:
        HTTPException: If API key not found
    """
    api_key = (
        db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == user_id).first()
    )

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="API key not found"
        )

    api_key.is_revoked = True
    db.commit()
    db.refresh(api_key)

    return api_key
