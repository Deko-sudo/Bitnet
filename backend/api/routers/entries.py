# -*- coding: utf-8 -*-
"""Password entries API router."""

import hashlib
import hmac
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db
from backend.core.crypto_core import CryptoCore, DecryptionError, zero_memory
from backend.database.entry_service import EntryService
from backend.database.models import User
from backend.database.schemas import (
    EntryCreateSchema,
    EntryListItemSchema,
    EntryResponseSchema,
    EntryUpdateSchema,
)


router = APIRouter()


def _derive_login_hash(crypto: CryptoCore, password: str, salt: bytes) -> str:
    """Derive reproducible password verifier hash from password and user salt."""
    derived_key = bytearray(crypto.derive_master_key(password, salt))
    try:
        return hashlib.sha256(derived_key).hexdigest()
    finally:
        zero_memory(derived_key)


def _require_user(db: Session, user_id: int) -> User:
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


def _build_entry_service(
    db: Session,
    user: User,
    master_password: str,
) -> EntryService:
    crypto = CryptoCore()
    candidate_hash = _derive_login_hash(crypto, master_password, user.salt)
    if not hmac.compare_digest(candidate_hash, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    def key_provider() -> bytearray:
        return bytearray(crypto.derive_master_key(master_password, user.salt))

    return EntryService(db_session=db, key_provider=key_provider)


def _entry_to_response(entry, decrypted) -> EntryResponseSchema:
    return EntryResponseSchema(
        id=entry.id,
        user_id=entry.user_id,
        title=decrypted.title,
        username=decrypted.username,
        url=decrypted.url,
        notes=decrypted.notes,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


def _entry_to_list_item(entry, decrypted) -> EntryListItemSchema:
    return EntryListItemSchema(
        id=entry.id,
        user_id=entry.user_id,
        title=decrypted.title,
        url=decrypted.url,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


def _safe_secret(value: Optional[object]) -> Optional[str]:
    if value is None:
        return None
    get_secret = getattr(value, "get_secret_value", None)
    if callable(get_secret):
        return get_secret()
    return str(value)


@router.get("/", response_model=List[EntryListItemSchema])
def list_entries(
    user_id: int,
    x_master_password: str = Header(..., alias="X-Master-Password"),
    db: Session = Depends(get_db),
) -> List[EntryListItemSchema]:
    user = _require_user(db, user_id)
    service = _build_entry_service(db, user, x_master_password)
    try:
        entries = service.get_entries(user_id)
        result: List[EntryListItemSchema] = []
        for entry in entries:
            try:
                decrypted = service.decrypt_entry(entry)
            except DecryptionError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                ) from exc
            result.append(_entry_to_list_item(entry, decrypted))
        return result
    finally:
        service.close()


@router.post("/", response_model=EntryResponseSchema, status_code=status.HTTP_201_CREATED)
def create_entry(
    payload: EntryCreateSchema,
    user_id: int,
    x_master_password: str = Header(..., alias="X-Master-Password"),
    db: Session = Depends(get_db),
) -> EntryResponseSchema:
    user = _require_user(db, user_id)
    service = _build_entry_service(db, user, x_master_password)
    try:
        entry = service.create_entry(
            user_id=user_id,
            title=payload.title,
            password=payload.password.get_secret_value(),
            username=payload.username,
            url=payload.url,
            notes=payload.notes,
        )
        decrypted = service.decrypt_entry(entry)
        return _entry_to_response(entry, decrypted)
    except DecryptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        ) from exc
    finally:
        service.close()


@router.get("/{entry_id}", response_model=EntryResponseSchema)
def get_entry(
    entry_id: int,
    user_id: int,
    x_master_password: str = Header(..., alias="X-Master-Password"),
    db: Session = Depends(get_db),
) -> EntryResponseSchema:
    user = _require_user(db, user_id)
    service = _build_entry_service(db, user, x_master_password)
    try:
        entry = service.get_entry_by_id(entry_id, user_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        decrypted = service.decrypt_entry(entry)
        return _entry_to_response(entry, decrypted)
    except DecryptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        ) from exc
    finally:
        service.close()


@router.patch("/{entry_id}", response_model=EntryResponseSchema)
def update_entry(
    entry_id: int,
    payload: EntryUpdateSchema,
    user_id: int,
    x_master_password: str = Header(..., alias="X-Master-Password"),
    db: Session = Depends(get_db),
) -> EntryResponseSchema:
    user = _require_user(db, user_id)
    service = _build_entry_service(db, user, x_master_password)
    try:
        updated = service.update_entry(
            entry_id=entry_id,
            user_id=user_id,
            title=payload.title,
            password=_safe_secret(payload.password),
            username=payload.username,
            url=payload.url,
            notes=payload.notes,
        )
        if updated is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        decrypted = service.decrypt_entry(updated)
        return _entry_to_response(updated, decrypted)
    except DecryptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        ) from exc
    finally:
        service.close()


@router.delete("/{entry_id}")
def delete_entry(
    entry_id: int,
    user_id: int,
    x_master_password: str = Header(..., alias="X-Master-Password"),
    db: Session = Depends(get_db),
) -> dict:
    user = _require_user(db, user_id)
    service = _build_entry_service(db, user, x_master_password)
    try:
        deleted = service.delete_entry(entry_id=entry_id, user_id=user_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Entry not found",
            )
        return {"deleted": True}
    finally:
        service.close()
