# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Generator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, SecretStr
from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.core.crypto_bridge import LockedBuffer, bridge, zeroize_mutable_buffer
from backend.core.encryption_helper import EncryptionHelper
from backend.database.models import User
from backend.database.session import get_db

router = APIRouter()


class UserRegisterSchema(BaseModel):
    username: str
    email: EmailStr
    password: SecretStr  # Zero-Trust constraint


class UserLoginSchema(BaseModel):
    username: str
    password: SecretStr  # Zero-Trust constraint


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str


@dataclass
class RequestCryptoContext:
    user_id: int
    master_key: LockedBuffer

    def duplicate_key(self) -> LockedBuffer:
        return self.master_key.duplicate()


def _server_wrap_key_path() -> str:
    wrap_key_path = os.getenv("BITNET_SERVER_WRAP_KEY_FILE")
    if not wrap_key_path:
        raise RuntimeError("BITNET_SERVER_WRAP_KEY_FILE is not configured")
    return wrap_key_path


def _read_secret_file(path: str) -> bytearray:
    file_size = os.path.getsize(path)
    if file_size <= 0:
        raise RuntimeError(f"Secret file {path} is empty")

    out = bytearray(file_size)
    with open(path, "rb", buffering=0) as handle:
        bytes_read = handle.readinto(out)

    if bytes_read != file_size:
        zeroize_mutable_buffer(out)
        raise RuntimeError(f"Expected {file_size} bytes from {path}, received {bytes_read}")

    return out


def _load_server_wrap_key() -> LockedBuffer:
    wrap_key_bytes = _read_secret_file(_server_wrap_key_path())
    try:
        return bridge.lock_bytes(wrap_key_bytes, wipe_input=True)
    finally:
        zeroize_mutable_buffer(wrap_key_bytes)


def _derive_login_hash(password: SecretStr | str, salt: bytes) -> str:
    password_value = password.get_secret_value() if isinstance(password, SecretStr) else password
    password_buf = bytearray(password_value.encode("utf-8"))
    derived = bridge.argon2_derive_key(password_buf, salt, wipe_password=True)
    try:
        derived_bytes = bridge.locked_buffer_to_bytearray(derived)
        try:
            return hashlib.sha256(derived_bytes).hexdigest()
        finally:
            zeroize_mutable_buffer(derived_bytes)
    finally:
        derived.close()


def _unwrap_master_key(user: User) -> LockedBuffer:
    wrap_key = _load_server_wrap_key()
    try:
        return bridge.aes_gcm_decrypt(
            wrap_key,
            user.wrapped_master_key_cipher,
            user.wrapped_master_key_nonce,
            user.wrapped_master_key_tag,
        )
    finally:
        wrap_key.close()


def _extract_bearer_token(request: Request) -> bytearray:
    for header_name, header_value in request.scope.get("headers", []):
        if header_name.lower() != b"authorization":
            continue
        if not header_value.lower().startswith(b"bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header must be Bearer token",
            )
        return bytearray(header_value[7:])

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authorization header is required",
    )


def get_request_crypto_context(
    request: Request,
    db: Session = Depends(get_db),
) -> Generator[RequestCryptoContext, None, None]:
    token_buf = _extract_bearer_token(request)
    try:
        token_hash = hashlib.sha256(token_buf).hexdigest()
    finally:
        zeroize_mutable_buffer(token_buf)

    user = db.query(User).filter(User.session_token_hash == token_hash).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
        )

    master_key = _unwrap_master_key(user)
    try:
        yield RequestCryptoContext(user_id=user.id, master_key=master_key)
    finally:
        master_key.close()


def get_user_context(
    context: RequestCryptoContext = Depends(get_request_crypto_context),
) -> tuple[int, EncryptionHelper]:
    helper = EncryptionHelper(key_provider=context.duplicate_key)
    return context.user_id, helper


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegisterSchema, db: Session = Depends(get_db)) -> UserResponse:
    existing_user = db.query(User).filter(
        or_(
            User.username == user_data.username,
            User.email == str(user_data.email),
        )
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with same username or email already exists",
        )

    salt = secrets.token_bytes(16)
    password_hash = _derive_login_hash(user_data.password, salt)
    master_key = bridge.generate_random_locked(32)
    wrap_key = _load_server_wrap_key()
    try:
        envelope = bridge.aes_gcm_encrypt(wrap_key, master_key, wipe_plaintext=False)
    finally:
        wrap_key.close()
        master_key.close()

    user = User(
        username=user_data.username,
        email=str(user_data.email),
        password_hash=password_hash,
        salt=salt,
        wrapped_master_key_cipher=envelope.ciphertext,
        wrapped_master_key_nonce=envelope.nonce,
        wrapped_master_key_tag=envelope.tag,
        session_token_hash=None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)


@router.post("/login", response_model=LoginResponse)
def login(credentials: UserLoginSchema, db: Session = Depends(get_db)) -> LoginResponse:
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    candidate_hash = _derive_login_hash(credentials.password, user.salt)
    if not hmac.compare_digest(candidate_hash, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Fail closed if the wrapped master key blob is not decryptable.
    master_key = _unwrap_master_key(user)
    master_key.close()

    token = secrets.token_urlsafe(32)
    user.session_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db.commit()

    return LoginResponse(
        access_token=token,
        user_id=user.id,
        username=user.username,
    )
