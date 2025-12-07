"""
API Key service layer.
Business logic for API key generation, validation, and management.
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID
from app.models.auth import APIKey
from app.utils.security import generate_api_key, get_key_hash
from app.config import settings

# Simple in-memory cache: {key_hash: (api_key_dict, expiration_timestamp)}
API_KEY_CACHE = {}


def create_api_key(
    db: Session, user_id: UUID, name: str, expires_in_days: int = None
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

    # Check if key with same name already exists for this user
    existing_key = (
        db.query(APIKey).filter(APIKey.user_id == user_id, APIKey.name == name).first()
    )
    if existing_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="API key with this name already exists",
        )

    # Generate unique API key
    plain_key = generate_api_key()
    key_hash = get_key_hash(plain_key)

    # Calculate expiration date
    expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    # Create API key record
    db_api_key = APIKey(
        key_hash=key_hash, name=name, user_id=user_id, expires_at=expires_at
    )

    db.add(db_api_key)
    db.commit()
    db.refresh(db_api_key)

    # Attach plain key to object for one-time display (not persisted)
    db_api_key.key = plain_key

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
    key_hash = get_key_hash(key)

    # Check cache
    if key_hash in API_KEY_CACHE:
        cached_data, valid_until = API_KEY_CACHE[key_hash]
        if datetime.utcnow() < valid_until:
            # Update last_used_at in background?
            # For strictness we skip DB write on cache hit for speed, or use a background task.
            # Here we prioritized speed, so we skip DB write.
            return cached_data
        else:
            del API_KEY_CACHE[key_hash]

    api_key = (
        db.query(APIKey)
        .filter(APIKey.key_hash == key_hash, APIKey.is_revoked == False)
        .first()
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

    result = {
        "api_key_id": api_key.id,
        "user_id": api_key.user_id,
        "name": api_key.name,
        "type": "service",
    }

    # Cache for 5 minutes
    API_KEY_CACHE[key_hash] = (result, datetime.utcnow() + timedelta(minutes=5))

    return result


def list_user_api_keys(db: Session, user_id: UUID) -> List[APIKey]:
    """
    Get all API keys for a user.

    Args:
        db: Database session
        user_id: ID of the user

    Returns:
        List of API key objects
    """
    return db.query(APIKey).filter(APIKey.user_id == user_id).all()


def revoke_api_key(db: Session, key_id: UUID, user_id: UUID) -> APIKey:
    """
    Revoke an API key (Soft Delete).

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

    # Invalidate cache
    # Since we don't have the original key string here, we can't easily remove it from cache
    # if the cache key is the hash.
    # However, since we query DB on cache miss, and revocation updates DB,
    # we just need to ensure we don't rely on stale cache.
    # But wait, if cached, we return cached data and ignore DB.
    # So we MUST invalidate cache.
    # Problem: 'revoke_api_key' input is 'key_id', not 'key'.
    # We can't derive 'key_hash' from 'key_id'.
    # Solution: We can't selectively invalidate efficiently without storing map id->hash.
    # OR we accept 5 min delay in revocation (acceptable for "Speed").
    # OR we clear entire cache check (heavy).
    # OR we add key_hash to cache value so we can iterate.

    # Let's iterate cache to remove by ID (O(N) but N is cache size).
    keys_to_remove = []
    for k, (v, _) in API_KEY_CACHE.items():
        if v["api_key_id"] == key_id:
            keys_to_remove.append(k)

    for k in keys_to_remove:
        del API_KEY_CACHE[k]

    return api_key


def delete_api_key(db: Session, key_id: UUID, user_id: UUID):
    """
    Parmanently remove an API key (Hard Delete).

    Args:
        db: Database session
        key_id: ID of the API key to delete
        user_id: ID of the user (for authorization check)

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

    # Invalidate cache before delete
    keys_to_remove = []
    for k, (v, _) in API_KEY_CACHE.items():
        if v["api_key_id"] == key_id:
            keys_to_remove.append(k)

    for k in keys_to_remove:
        del API_KEY_CACHE[k]

    db.delete(api_key)
    db.commit()
