# -*- coding: utf-8 -*-
"""Authentication API router."""

import hashlib
import hmac
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db
from backend.core.crypto_core import CryptoCore, zero_memory
from backend.database.models import User
from backend.database.schemas import LoginRequest, LoginResponse, UserCreate, UserResponse


router = APIRouter()


def _derive_login_hash(crypto: CryptoCore, password: str, salt: bytes) -> str:
    """Derive reproducible password verifier hash from password and user salt."""
    derived_key = bytearray(crypto.derive_master_key(password, salt))
    try:
        return hashlib.sha256(derived_key).hexdigest()
    finally:
        zero_memory(derived_key)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> UserResponse:
    """Register new user account."""
    existing_user = db.execute(
        select(User).where(
            or_(
                User.username == payload.username,
                User.email == str(payload.email),
            )
        )
    ).scalar_one_or_none()
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with same username or email already exists",
        )

    crypto = CryptoCore()
    password_value = payload.password.get_secret_value()
    user_salt = crypto.generate_salt()
    password_hash = _derive_login_hash(crypto, password_value, user_salt)

    user = User(
        username=payload.username,
        email=str(payload.email),
        password_hash=password_hash,
        salt=user_salt,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    """Authenticate user and issue short-lived API token placeholder."""
    user = db.execute(
        select(User).where(User.username == payload.username)
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    crypto = CryptoCore()
    password_value = payload.password.get_secret_value()
    candidate_hash = _derive_login_hash(crypto, password_value, user.salt)
    if not hmac.compare_digest(candidate_hash, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    return LoginResponse(
        access_token=secrets.token_urlsafe(32),
        user_id=user.id,
        username=user.username,
    )
