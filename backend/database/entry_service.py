# -*- coding: utf-8 -*-
"""
Async entry service for encrypted vault records.

This service is intentionally aligned with the Rust-backed crypto bridge:
callers provide a request-scoped ``LockedBuffer`` master key and every field
operation goes through ``backend.core.encryption_helper`` pure functions.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import SecretStr
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer, bridge, zeroize_mutable_buffer
from backend.core.encryption_helper import (
    decrypt_entry_data,
    encrypt_all_entry_fields,
    encrypt_entry_data,
    generate_search_index,
)
from backend.database.models import PasswordEntry, User
from backend.database.schemas import (
    EntryCreateSchema,
    EntryResponseRaw,
    EntryResponseSchema,
    EntryUpdateSchema,
)


class EntryNotFoundError(Exception):
    """Raised when a requested entry does not exist or is soft-deleted."""


class EntryConflictError(Exception):
    """Raised when optimistic concurrency detects a stale update."""


def _secret_to_bytearray(value: SecretStr | str) -> bytearray:
    raw_value = value.get_secret_value() if isinstance(value, SecretStr) else value
    return bytearray(raw_value.encode("utf-8"))


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


class EntryService:
    """CRUD facade for ``PasswordEntry`` rows encrypted with a ``LockedBuffer`` key."""

    def __init__(self, session: AsyncSession, master_key: LockedBuffer):
        self.session = session
        self.master_key = master_key

    async def list_entries_async(
        self, user_id: int, skip: int = 0, limit: int = 100
    ) -> list[PasswordEntry]:
        stmt = (
            select(PasswordEntry)
            .where(
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False,  # noqa: E712
            )
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def search_entries_async(
        self, user_id: int, blind_index: str, skip: int = 0, limit: int = 100
    ) -> list[PasswordEntry]:
        stmt = (
            select(PasswordEntry)
            .where(
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False,  # noqa: E712
                PasswordEntry.title_search == blind_index,
            )
            .offset(skip)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_entry_async(self, user_id: int, data: EntryCreateSchema) -> PasswordEntry:
        title_for_index = _secret_to_bytearray(data.title)
        title_for_encrypt = _secret_to_bytearray(data.title)
        password = _secret_to_bytearray(data.password)
        username = _secret_to_bytearray(data.username) if data.username else None
        url = _secret_to_bytearray(data.url) if data.url else None
        notes = _secret_to_bytearray(data.notes) if data.notes else None

        try:
            blind_index = generate_search_index(self.master_key, title_for_index)
            encrypted = encrypt_all_entry_fields(
                self.master_key,
                title=title_for_encrypt,
                username=username,
                password=password,
                url=url,
                notes=notes,
            )
        finally:
            for buf in (title_for_index, title_for_encrypt, password, username, url, notes):
                if buf is not None:
                    zeroize_mutable_buffer(buf)

        entry = PasswordEntry(
            user_id=user_id,
            title_search=blind_index,
            title_cipher=encrypted["title_cipher"],
            title_nonce=encrypted["title_nonce"],
            username_cipher=encrypted["username_cipher"],
            username_nonce=encrypted["username_nonce"],
            password_cipher=encrypted["password_cipher"],
            password_nonce=encrypted["password_nonce"],
            url_cipher=encrypted["url_cipher"],
            url_nonce=encrypted["url_nonce"],
            notes_cipher=encrypted["notes_cipher"],
            notes_nonce=encrypted["notes_nonce"],
        )
        self.session.add(entry)
        await self.session.commit()
        await self.session.refresh(entry)
        return entry

    async def update_entry_async(
        self,
        user_id: int,
        entry_id: int,
        update_data: EntryUpdateSchema,
        client_updated_at: Optional[datetime] = None,
    ) -> PasswordEntry:
        entry = await self._fetch_active_entry(user_id, entry_id)

        if client_updated_at is not None and entry.updated_at > client_updated_at:
            raise EntryConflictError(f"Entry {entry_id} was modified after the client's last sync.")

        update_dict = update_data.model_dump(exclude_unset=True)
        if not update_dict:
            return entry

        for field_name in ("title", "username", "password", "url", "notes"):
            if field_name not in update_dict:
                continue

            new_value = getattr(update_data, field_name)
            if new_value is None:
                if field_name not in ("title", "password"):
                    setattr(entry, f"{field_name}_cipher", None)
                    setattr(entry, f"{field_name}_nonce", None)
                continue

            plaintext = _secret_to_bytearray(new_value)
            try:
                cipher_hex, nonce_hex = encrypt_entry_data(self.master_key, plaintext)
            finally:
                zeroize_mutable_buffer(plaintext)

            setattr(entry, f"{field_name}_cipher", cipher_hex)
            setattr(entry, f"{field_name}_nonce", nonce_hex)

            if field_name == "title":
                title_for_index = _secret_to_bytearray(new_value)
                try:
                    entry.title_search = generate_search_index(self.master_key, title_for_index)
                finally:
                    zeroize_mutable_buffer(title_for_index)

        await self.session.commit()
        await self.session.refresh(entry)
        return entry

    async def delete_entry_async(self, user_id: int, entry_id: int) -> bool:
        entry = await self._fetch_active_entry(user_id, entry_id)
        entry.is_deleted = True
        entry.deleted_at = datetime.now(timezone.utc)
        await self.session.commit()
        return True

    async def get_entry_raw_async(self, user_id: int, entry_id: int) -> EntryResponseRaw:
        entry = await self._fetch_active_entry(user_id, entry_id)

        title = self._decrypt_to_bytearray(entry.title_cipher, entry.title_nonce)
        password = self._decrypt_to_bytearray(entry.password_cipher, entry.password_nonce)
        username = self._decrypt_optional(entry.username_cipher, entry.username_nonce)
        url = self._decrypt_optional(entry.url_cipher, entry.url_nonce)
        notes = self._decrypt_optional(entry.notes_cipher, entry.notes_nonce)

        return EntryResponseRaw(
            id=entry.id,
            user_id=entry.user_id,
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
        )

    async def get_entry_response_async(self, user_id: int, entry_id: int) -> EntryResponseSchema:
        raw = await self.get_entry_raw_async(user_id, entry_id)
        try:
            return EntryResponseSchema(
                id=raw.id,
                user_id=raw.user_id,
                title=SecretStr(raw.title.decode("utf-8")),
                username=(SecretStr(raw.username.decode("utf-8")) if raw.username else None),
                password=SecretStr(raw.password.decode("utf-8")),
                url=SecretStr(raw.url.decode("utf-8")) if raw.url else None,
                notes=SecretStr(raw.notes.decode("utf-8")) if raw.notes else None,
                created_at=raw.created_at,
                updated_at=raw.updated_at,
            )
        finally:
            raw.wipe()

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
        Update the login verifier without re-encrypting vault entries.

        In the current server-wrap architecture, vault rows are encrypted with
        the persisted user master key. The user's password is only a login
        verifier, so changing it must update ``salt`` and ``password_hash``.
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

    def _decrypt_to_bytearray(self, cipher_hex: str, nonce_hex: str) -> bytearray:
        locked: LockedBuffer | None = None
        try:
            locked = decrypt_entry_data(self.master_key, cipher_hex, nonce_hex)
            return bridge.locked_buffer_to_bytearray(locked)
        finally:
            if locked is not None:
                locked.close()

    def _decrypt_optional(
        self, cipher_hex: Optional[str], nonce_hex: Optional[str]
    ) -> Optional[bytearray]:
        if cipher_hex is None or nonce_hex is None:
            return None
        return self._decrypt_to_bytearray(cipher_hex, nonce_hex)
