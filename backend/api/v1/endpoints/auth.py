# -*- coding: utf-8 -*-
"""
Authentication endpoints — Zero-Trust, Rust-backed crypto.

* Passwords are never stored or kept as Python ``str`` longer than necessary.
* The master key is decrypted into a ``LockedBuffer`` and threaded through
  every request that requires encryption/decryption.
* Session tokens are SHA-256 hashes of cryptographically random secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, SecretStr
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer, bridge, zeroize_mutable_buffer
from backend.core.security_utils import RateLimiter
from backend.database.models import User
from backend.database.session import get_db

router = APIRouter()

_login_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60, block_duration_seconds=300)
_register_rate_limiter = RateLimiter(max_attempts=3, window_seconds=300, block_duration_seconds=900)

_TRUST_PROXY = os.getenv("BITNET_TRUST_PROXY", "").lower() in ("1", "true", "yes")


def _get_client_ip(request: Request) -> str:
    if _TRUST_PROXY:
        return (
            request.headers.get("X-Real-IP", "").strip()
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class UserRegisterSchema(BaseModel):
    username: str
    email: EmailStr
    password: SecretStr


class UserLoginSchema(BaseModel):
    username: str
    password: SecretStr


class UserResponse(BaseModel):
    id: int
    username: str
    email: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str


# ---------------------------------------------------------------------------
# Crypto context — threaded through every protected endpoint
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CryptoContext:
    """Carries the decrypted master key for the lifetime of one request.

    The ``master_key`` is a Rust-managed ``LockedBuffer`` that resides in
    non-pageable, mlock'd memory.  It **must** be closed when the request
    finishes (handled by ``get_current_user``).
    """

    user_id: int
    username: str
    master_key: LockedBuffer


# ---------------------------------------------------------------------------
# Low-level crypto helpers
# ---------------------------------------------------------------------------


def _derive_password_hash(password_buf: bytearray, salt: bytes) -> str:
    """Derive an Argon2 hash for password verification.

    The ``password_buf`` is **always** zeroized before this function returns,
    regardless of success or failure.

    Returns
    -------
    hex-encoded SHA-256 digest of the Argon2 output (used as DB password_hash).
    """
    derived: LockedBuffer | None = None
    try:
        derived = bridge.argon2_derive_key(password_buf, salt, wipe_password=True)
        derived_bytes = bridge.locked_buffer_to_bytearray(derived)
        try:
            return hashlib.sha256(derived_bytes).hexdigest()
        finally:
            zeroize_mutable_buffer(derived_bytes)
    finally:
        if derived is not None:
            derived.close()


_server_wrap_key: LockedBuffer | None = None


def _load_server_wrap_key() -> LockedBuffer:
    global _server_wrap_key
    if _server_wrap_key is not None:
        return _server_wrap_key

    wrap_key_path = os.getenv("BITNET_SERVER_WRAP_KEY_FILE")
    if not wrap_key_path:
        raise RuntimeError(
            "BITNET_SERVER_WRAP_KEY_FILE environment variable is not set"
        )

    file_size = os.path.getsize(wrap_key_path)
    if file_size <= 0:
        raise RuntimeError(f"Wrap key file is empty: {wrap_key_path}")

    raw = bytearray(file_size)
    with open(wrap_key_path, "rb", buffering=0) as fh:
        read = fh.readinto(raw)
    if read != file_size:
        zeroize_mutable_buffer(raw)
        raise RuntimeError(f"Short read from wrap key file: {read} != {file_size}")

    try:
        _server_wrap_key = bridge.lock_bytes(raw, wipe_input=True)
    finally:
        zeroize_mutable_buffer(raw)
    return _server_wrap_key


def _unwrap_master_key_for_user(user: User) -> LockedBuffer:
    """Decrypt the user's wrapped master key using the server wrap key.

    This is the gate between authentication and data access.  If decryption
    fails (corrupted data, wrong server key, tampered DB), the caller must
    treat it as an authentication failure — **fail closed**.

    Returns
    -------
    LockedBuffer containing the user's 32-byte master key.

    Raises
    ------
    HTTPException(401)
        If the wrapped key cannot be decrypted.
    """
    server_key = _load_server_wrap_key()
    try:
        return bridge.aes_gcm_decrypt(
            server_key,
            user.wrapped_master_key_cipher,
            user.wrapped_master_key_nonce,
            user.wrapped_master_key_tag,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unable to decrypt master key — access denied",
        )


# ---------------------------------------------------------------------------
# Token extraction
# ---------------------------------------------------------------------------


def _extract_bearer_token(request: Request) -> bytearray:
    """Pull the raw token bytes from the Authorization header.

    Returns a ``bytearray`` so it can be zeroized after hashing.
    """
    for header_name, header_value in request.scope.get("headers", []):
        if header_name.lower() != b"authorization":
            continue
        if not header_value.lower().startswith(b"bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header must use the Bearer scheme",
            )
        return bytearray(header_value[7:])

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing Authorization header",
    )


# ---------------------------------------------------------------------------
# FastAPI dependency — the single source of auth for all protected routes
# ---------------------------------------------------------------------------


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AsyncGenerator[CryptoContext, None]:
    """Authenticate the bearer token and yield a ``CryptoContext``.

    Flow
    ----
    1. Extract Bearer token from request headers.
    2. SHA-256 hash the token → look up ``User`` by ``session_token_hash``.
    3. Decrypt (unwrap) the user's master key with the server wrap key.
    4. Yield ``CryptoContext(user_id, username, master_key)``.
    5. **Always** close the master key in ``finally``, even on errors.

    Raises
    ------
    HTTPException(401)
        Invalid/missing token or unable to decrypt master key.
    """
    # 1. Extract and hash token
    token_buf = _extract_bearer_token(request)
    try:
        token_hash = hashlib.sha256(token_buf).hexdigest()
    finally:
        zeroize_mutable_buffer(token_buf)

    # 2. Look up user
    stmt = select(User).where(User.session_token_hash == token_hash)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired bearer token",
        )
    # Check session expiry
    if user.session_expires_at is not None:
        expires_at = user.session_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired. Please log in again.",
            )

    # 3. Unwrap master key (fail-closed on error)
    master_key = _unwrap_master_key_for_user(user)

    # 4–5. Yield and guarantee cleanup
    try:
        yield CryptoContext(
            user_id=user.id,
            username=user.username,
            master_key=master_key,
        )
    finally:
        master_key.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    request: Request,
    data: UserRegisterSchema,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    client_ip = _get_client_ip(request)

    if not _register_rate_limiter.can_attempt(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later.",
            headers={"Retry-After": str(_register_rate_limiter.get_delay(client_ip))},
        )
    """Register a new user with Argon2 password hashing and encrypted master key."""

    # Check uniqueness
    stmt = select(User).where(
        or_(
            User.username == data.username,
            User.email == str(data.email),
        )
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Registration failed. Please try again.",
        )

    # Derive login password hash
    salt = secrets.token_bytes(16)
    password_buf = bytearray(data.password.get_secret_value().encode("utf-8"))
    try:
        password_hash = _derive_password_hash(password_buf, salt)
    finally:
        zeroize_mutable_buffer(password_buf)

    # Generate and wrap the user's master key with the server wrap key
    master_key = bridge.generate_random_locked(32)
    server_key = _load_server_wrap_key()
    try:
        envelope = bridge.aes_gcm_encrypt(server_key, master_key, wipe_plaintext=False)
    finally:
        master_key.close()

    user = User(
        username=data.username,
        email=str(data.email),
        password_hash=password_hash,
        salt=salt,
        wrapped_master_key_cipher=envelope.ciphertext,
        wrapped_master_key_nonce=envelope.nonce,
        wrapped_master_key_tag=envelope.tag,
        session_token_hash=None,
    )
    try:
        db.add(user)
        await db.commit()
        await db.refresh(user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Registration failed. Please try again.",
        )

    return UserResponse(id=user.id, username=user.username, email=user.email)


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    creds: UserLoginSchema,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Authenticate with username/password and receive a bearer token.

    Flow
    ----
    0. Rate-limit check by client IP.
    1. Fetch ``User`` by username (constant-time dummy hash if not found).
    2. Derive Argon2 key from the provided password + stored salt.
    3. Compare derived hash with stored ``password_hash`` (constant-time).
    4. Decrypt the wrapped master key to verify it is still valid (fail-closed).
    5. Generate a random session token, store its SHA-256 hash in the DB.
    6. Return the plaintext token to the client.
    """
    client_ip = _get_client_ip(request)

    if not _login_rate_limiter.can_attempt(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(_login_rate_limiter.get_delay(client_ip))},
        )
    stmt = select(User).where(User.username == creds.username).with_for_update()
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if user is None:
        # Constant-time: derive a dummy hash to avoid timing-based user enumeration
        _login_rate_limiter.register_failed(client_ip)
        _derive_password_hash(bytearray(b"dummy"), secrets.token_bytes(16))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Derive and compare password hash
    password_buf = bytearray(creds.password.get_secret_value().encode("utf-8"))
    try:
        candidate_hash = _derive_password_hash(password_buf, user.salt)
    finally:
        zeroize_mutable_buffer(password_buf)

    if not hmac.compare_digest(candidate_hash, user.password_hash):
        _login_rate_limiter.register_failed(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Verify the master key is decryptable before issuing a session (fail-closed)
    mk = _unwrap_master_key_for_user(user)
    mk.close()

    # Issue session token
    _login_rate_limiter.register_success(client_ip)
    token = secrets.token_urlsafe(32)
    user.session_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    user.session_expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    await db.commit()

    return LoginResponse(
        access_token=token,
        user_id=user.id,
        username=user.username,
    )


@router.get("/me", response_model=UserResponse)
async def me(
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> UserResponse:
    """Return the currently authenticated user's public profile."""
    stmt = select(User).where(User.id == ctx.user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    ctx: CryptoContext = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Invalidate the current session token."""
    stmt = select(User).where(User.id == ctx.user_id).with_for_update()
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if user is not None:
        user.session_token_hash = None
        user.session_expires_at = None
        await db.commit()
