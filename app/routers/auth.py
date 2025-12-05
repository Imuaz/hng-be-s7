"""
Authentication routes for user signup and login.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.auth import UserSignup, UserLogin, UserResponse, Token
from app.services.auth import create_user, authenticate_user, create_user_token

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def signup(user_data: UserSignup, db: Session = Depends(get_db)):
    """
    Register a new user account.

    **Request Body:**
    - `email`: Valid email address (must be unique)
    - `username`: Username (3-50 characters, must be unique)
    - `password`: Password (minimum 6 characters)

    **Returns:**
    - User information (id, email, username, created_at, is_active)

    **Errors:**
    - `400 Bad Request`: Email or username already exists
    """
    user = create_user(db, user_data)
    return user


@router.post("/login", response_model=Token)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """
    Login with username and password to receive a JWT access token.

    **Request Body:**
    - `username`: User's username
    - `password`: User's password

    **Returns:**
    - `access_token`: JWT token for authentication
    - `token_type`: "bearer"

    **Errors:**
    - `401 Unauthorized`: Invalid credentials
    - `400 Bad Request`: Inactive user account

    **Usage:**
    Include the token in subsequent requests using the Authorization header:
    ```
    Authorization: Bearer <access_token>
    ```
    """
    user = authenticate_user(db, user_data.username, user_data.password)
    access_token = create_user_token(user)

    return {"access_token": access_token, "token_type": "bearer"}
