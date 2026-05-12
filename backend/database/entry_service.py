# -*- coding: utf-8 -*-
"""
Async pass-through entry service for E2EE vault records.

The service stores and returns client-encrypted envelopes only. It does not
derive entry keys, decrypt vault data, inspect plaintext, or depend on a
request-scoped master key for entry CRUD.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer, bridge, zeroize_mutable_buffer
from backend.database.models import PasswordEntry, User
from backend.database.schemas import (
    EntryEnvelopeCreateSchema,
    EntryEnvelopeResponseSchema,
    EntryEnvelopeUpdateSchema,
)


class EntryNotFoundError(Exception):
    """Raised when a requested entry does not exist or is soft-deleted."""


class EntryConflictError(Exception):
    """Raised when optimistic concurrency detects a stale update."""


def _derive_login_hash(password: str, salt: bytes) -> str:
    password_buf = bytearray(password.encode("utf-8"))
    derived: LockedBuffer | None = None
    try:
        derived = bridge.argon2_derive_key(password_buf, salt, wipe_password=True)
        derived_bytes = bridge.locked_buffer_to_bytearray(derived)
        try:
            return hashlib.sha256(derived_bytes).hexdigest()
        finally:
            zeroize_mutable_buffer(derived_bytes)
    finally:
        zeroize_mutable_buffer(password_buf)
        if derived is not None:
            derived.close()


def _metadata_to_json(metadata: dict | None) -> str:
    return json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _metadata_from_json(metadata: str | None) -> dict:
    if not metadata:
        return {}
    loaded = json.loads(metadata)
    return loaded if isinstance(loaded, dict) else {}


def _decode_blob(value: str, field_name: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} must be valid base64.") from exc
    if not decoded:
        raise ValueError(f"{field_name} must not be empty.")
    return decoded


def _encode_blob(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class EntryService:
    """CRUD facade for opaque E2EE ``PasswordEntry`` envelopes."""

    def __init__(self, session: AsyncSession, master_key: object | None = None):
        self.session = session
        _ = master_key  # Accepted only for transitional caller compatibility.

    async def list_entries_async(
        self,
        user_id: int,
        skip: int = 0,
        limit: int = 100,
    ) -> list[PasswordEntry]:
        stmt = (
            select(PasswordEntry)
            .where(
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False,  # noqa: E712
            )
            .order_by(PasswordEntry.id)
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def search_entries_async(
        self,
        user_id: int,
        title_search: str,
        skip: int = 0,
        limit: int = 100,
    ) -> list[PasswordEntry]:
        stmt = (
            select(PasswordEntry)
            .where(
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False,  # noqa: E712
                PasswordEntry.title_search == title_search,
            )
            .order_by(PasswordEntry.id)
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_entry_async(
        self,
        user_id: int,
        data: EntryEnvelopeCreateSchema,
    ) -> PasswordEntry:
        entry = PasswordEntry(
            user_id=user_id,
            title_search=data.title_search,
            ciphertext=_decode_blob(data.ciphertext, "ciphertext"),
            iv=_decode_blob(data.iv, "iv"),
            auth_tag=_decode_blob(data.auth_tag, "auth_tag"),
            key_metadata=_metadata_to_json(data.key_metadata),
            title_cipher="",
            title_nonce="",
            password_cipher="",
            password_nonce="",
        )
        self.session.add(entry)
        await self.session.commit()
        await self.session.refresh(entry)
        return entry

    async def update_entry_async(
        self,
        user_id: int,
        entry_id: int,
        update_data: EntryEnvelopeUpdateSchema,
        client_updated_at: Optional[datetime] = None,
    ) -> PasswordEntry:
        entry = await self._fetch_active_entry(user_id, entry_id)

        if client_updated_at is not None and entry.updated_at > client_updated_at:
            raise EntryConflictError(f"Entry {entry_id} was modified after client sync.")

        update_dict = update_data.model_dump(exclude_unset=True)
        if not update_dict:
            return entry

        core_fields = {"ciphertext", "iv", "auth_tag"}
        if core_fields.intersection(update_dict) and not core_fields.issubset(update_dict):
            raise ValueError("ciphertext, iv, and auth_tag must be updated together.")

        if update_data.ciphertext is not None:
            entry.ciphertext = _decode_blob(update_data.ciphertext, "ciphertext")
            entry.iv = _decode_blob(update_data.iv or "", "iv")
            entry.auth_tag = _decode_blob(update_data.auth_tag or "", "auth_tag")

        if "key_metadata" in update_dict:
            entry.key_metadata = _metadata_to_json(update_data.key_metadata)
        if "title_search" in update_dict:
            entry.title_search = update_data.title_search

        await self.session.commit()
        await self.session.refresh(entry)
        return entry

    async def delete_entry_async(self, user_id: int, entry_id: int) -> bool:
        entry = await self._fetch_active_entry(user_id, entry_id)
        entry.is_deleted = True
        entry.deleted_at = datetime.now(timezone.utc)
        await self.session.commit()
        return True

    async def get_entry_envelope_async(
        self,
        user_id: int,
        entry_id: int,
    ) -> EntryEnvelopeResponseSchema:
        entry = await self._fetch_active_entry(user_id, entry_id)
        return self._to_envelope_response(entry)

    def to_envelope_response(self, entry: PasswordEntry) -> EntryEnvelopeResponseSchema:
        return self._to_envelope_response(entry)

    async def purge_deleted_entries_async(self, user_id: int, older_than_days: int = 30) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        stmt = delete(PasswordEntry).where(
            PasswordEntry.user_id == user_id,
            PasswordEntry.is_deleted == True,  # noqa: E712
            PasswordEntry.deleted_at <= cutoff,
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return int(result.rowcount or 0)

    async def change_master_password_async(
        self,
        user_id: int,
        old_password: str,
        new_password: str,
    ) -> None:
        """
        Update only the login verifier.

        E2EE vault rows are encrypted by clients, so a password change must not
        attempt server-side re-encryption of entry envelopes.
        """
        stmt = select(User).where(User.id == user_id)
        result = await self.session.execute(stmt)
        user = result.scalar_one_or_none()
        if user is None:
            raise ValueError("User not found.")

        old_hash = _derive_login_hash(old_password, user.salt)
        if not hmac.compare_digest(old_hash, user.password_hash):
            raise ValueError("Old password is incorrect.")

        new_salt = secrets.token_bytes(16)
        user.salt = new_salt
        user.password_hash = _derive_login_hash(new_password, new_salt)
        await self.session.commit()

    async def _fetch_active_entry(self, user_id: int, entry_id: int) -> PasswordEntry:
        stmt = select(PasswordEntry).where(
            PasswordEntry.id == entry_id,
            PasswordEntry.user_id == user_id,
            PasswordEntry.is_deleted == False,  # noqa: E712
        )
        result = await self.session.execute(stmt)
        entry = result.scalar_one_or_none()
        if entry is None:
            raise EntryNotFoundError(f"Entry {entry_id} not found.")
        return entry

    @staticmethod
    def _to_envelope_response(entry: PasswordEntry) -> EntryEnvelopeResponseSchema:
        if entry.ciphertext is None or entry.iv is None or entry.auth_tag is None:
            raise EntryNotFoundError("E2EE envelope is not available for this entry.")

        return EntryEnvelopeResponseSchema(
            id=entry.id,
            user_id=entry.user_id,
            ciphertext=_encode_blob(entry.ciphertext),
            iv=_encode_blob(entry.iv),
            auth_tag=_encode_blob(entry.auth_tag),
            key_metadata=_metadata_from_json(entry.key_metadata),
            title_search=entry.title_search,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
        )
