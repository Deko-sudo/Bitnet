# -*- coding: utf-8 -*-
from datetime import datetime
from typing import Optional

from sqlalchemy import Integer, String, DateTime, Boolean, ForeignKey, LargeBinary
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    entries: Mapped[list["PasswordEntry"]] = relationship("PasswordEntry", back_populates="user")


class PasswordEntry(Base):
    __tablename__ = "password_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    
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
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="entries")

class PasswordHistory(Base):
    __tablename__ = "password_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entry_id: Mapped[int] = mapped_column(ForeignKey("password_entries.id"), index=True, nullable=False)
    
    password_cipher: Mapped[str] = mapped_column(String, nullable=False)
    password_nonce: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    entry: Mapped["PasswordEntry"] = relationship("PasswordEntry", backref="history")
