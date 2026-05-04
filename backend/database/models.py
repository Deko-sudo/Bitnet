# -*- coding: utf-8 -*-
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

# Use the Base defined in BE1's audit_logger to ensure all models are on the same declarative Base
from backend.core.audit_logger import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_master_key_cipher: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_master_key_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_master_key_tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # TOTP Fields
    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    totp_last_counter: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    session_token_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    entries: Mapped[list["PasswordEntry"]] = relationship("PasswordEntry", back_populates="user")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)

    # Index for fast counting of failed attempts in the last N minutes
    __table_args__ = (Index("ix_login_attempts_at", "attempted_at"),)


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)  # argon2 hash
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class PasswordEntry(Base):
    __tablename__ = "password_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    version_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )

    title_search: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)

    title_cipher: Mapped[str] = mapped_column(String, nullable=False)
    title_nonce: Mapped[str] = mapped_column(String, nullable=False)

    username_cipher: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    username_nonce: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    password_cipher: Mapped[str] = mapped_column(String, nullable=False)
    password_nonce: Mapped[str] = mapped_column(String, nullable=False)

    url_cipher: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    url_nonce: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    notes_cipher: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    notes_nonce: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    user: Mapped["User"] = relationship("User", back_populates="entries")

    __mapper_args__ = {"version_id_col": version_id}


class PasswordHistory(Base):
    __tablename__ = "password_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entry_id: Mapped[int] = mapped_column(
        ForeignKey("password_entries.id"), index=True, nullable=False
    )

    # Storage contract (same as PasswordEntry):
    #   password_cipher = hex(ciphertext || auth_tag)   ← tag is implicit in the suffix
    #   password_nonce  = hex(12-byte GCM nonce)
    # This matches the output of encrypt_for_storage() in crypto_bridge.py.
    password_cipher: Mapped[str] = mapped_column(String, nullable=False)
    password_nonce: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    entry: Mapped["PasswordEntry"] = relationship("PasswordEntry", backref="history")


class WebAuthnCredential(Base):
    """FIDO2/WebAuthn hardware security key credential.

    Implements the **double-wrap** strategy for master key protection:

    1. The user's ``master_key`` (32-byte AES key) is wrapped with a per-device
       ``device_protector`` (random 32-byte AES key) via AES-GCM.
       → stored as ``wrapped_master_key_fido_{cipher,nonce,tag}``.

    2. The ``device_protector`` itself is then wrapped with the **server** wrap key
       (loaded from ``BITNET_SERVER_WRAP_KEY_FILE``).
       → stored as ``device_protector_{cipher,nonce,tag}``.

    To recover the user's master key during FIDO2 login:
        server_key → unwrap device_protector → unwrap master_key → LockedBuffer.

    If the server wrap key is rotated or the device is removed, only that single
    credential is affected — the user's primary (password-derived) master key
    remains intact.
    """

    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)

    # WebAuthn credential material (COSE-encoded)
    credential_id: Mapped[bytes] = mapped_column(
        LargeBinary, unique=True, index=True, nullable=False
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))

    # Double-wrap layer 1: master_key wrapped with device_protector (AES-GCM)
    wrapped_master_key_fido_cipher: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_master_key_fido_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_master_key_fido_tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Double-wrap layer 2: device_protector wrapped with server wrap key (AES-GCM)
    device_protector_cipher: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    device_protector_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    device_protector_tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Metadata
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship("User", backref="webauthn_credentials")
