# -*- coding: utf-8 -*-
"""
Entries CRUD API — Zero-Trust, Rust-backed encryption.

Every endpoint receives the user's master key as a ``LockedBuffer`` through the
``get_current_user`` dependency.  All plaintext buffers are ``bytearray`` and
are wiped immediately after they are passed to the encryption helper.

Optimistic concurrency control (``version_id``) is enforced on PATCH; stale
updates return **HTTP 409 Conflict**.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.exc import StaleDataError

from backend.api.v1.endpoints.auth import CryptoContext, get_current_user
from backend.core.crypto_bridge import LockedBuffer, zeroize_mutable_buffer
from backend.core.encryption_helper import (
    decrypt_all_entry_fields,
    decrypt_entry_data,
    encrypt_all_entry_fields,
    encrypt_entry_data,
    generate_search_index,
)
from backend.database.models import PasswordEntry, PasswordHistory
from backend.database.schemas import (
    EntryEnvelopeCreateSchema,
    EntryEnvelopeResponseSchema,
    EntryEnvelopeUpdateSchema,
    EntryCreateSchema,
    EntryListItemSchema,
    EntryResponseSchema,
    EntryUpdateSchema,
)
from backend.database.entry_service import EntryNotFoundError, EntryService
from backend.database.session import get_db
from backend.features.password_history_manager import HistoryResponseSchema

router = APIRouter()


# ===========================================================================
# Internal helpers
# ===========================================================================


def _secret_to_bytearray(value: SecretStr) -> bytearray:
    """Convert a Pydantic ``SecretStr`` to a ``bytearray`` for encryption."""
    return bytearray(value.get_secret_value().encode("utf-8"))


async def _fetch_active_entry(
    db: AsyncSession,
    entry_id: int,
    user_id: int,
) -> PasswordEntry:
    """Return a non-deleted entry owned by *user_id*, or raise 404."""
    stmt = select(PasswordEntry).where(
        PasswordEntry.id == entry_id,
        PasswordEntry.user_id == user_id,
        PasswordEntry.is_deleted == False,
    )
    result = await db.execute(stmt)
    entry = result.scalar_one_or_none()

    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Entry not found or has been deleted",
        )
    return entry


def _locked_to_bytearray(locked: LockedBuffer) -> bytearray:
    """Copy a ``LockedBuffer`` into a ``bytearray``. Caller MUST zeroize!"""
    buf = bytearray(len(locked))
    locked.copy_into(buf)
    return buf


def _locked_to_str(locked: LockedBuffer) -> str:
    """Copy a ``LockedBuffer`` into a string. The bytearray is zeroized internally,
    but the returned ``str`` is immutable and cannot be zeroized."""
    buf = _locked_to_bytearray(locked)
    try:
        return buf.decode("utf-8")
    finally:
        zeroize_mutable_buffer(buf)


def _read_entry_response(entry: PasswordEntry, key: LockedBuffer) -> EntryResponseSchema:
    """Decrypt all fields of *entry* and pack into an ``EntryResponseSchema``.

    Every decrypted ``bytearray`` is zeroized in the ``finally`` block of
    ``_build_response_schema``.
    """
    lbs, decrypted = decrypt_all_entry_fields(
        key,
        title_cipher=entry.title_cipher,
        title_nonce=entry.title_nonce,
        username_cipher=entry.username_cipher,
        username_nonce=entry.username_nonce,
        password_cipher=entry.password_cipher,
        password_nonce=entry.password_nonce,
        url_cipher=entry.url_cipher,
        url_nonce=entry.url_nonce,
        notes_cipher=entry.notes_cipher,
        notes_nonce=entry.notes_nonce,
    )
    try:
        return _build_response_schema(entry, decrypted)
    finally:
        lbs.close()


def _build_response_schema(
    entry: PasswordEntry,
    decrypted: dict[str, Optional[bytearray]],
) -> EntryResponseSchema:
    """Pack decrypted bytearrays into a Pydantic response and wipe them."""
    title_buf = decrypted.get("title")
    password_buf = decrypted.get("password")
    username_buf = decrypted.get("username")
    url_buf = decrypted.get("url")
    notes_buf = decrypted.get("notes")

    try:
        return EntryResponseSchema(
            id=entry.id,
            user_id=entry.user_id,
            title=SecretStr(title_buf.decode("utf-8")) if title_buf else SecretStr(""),
            username=(SecretStr(username_buf.decode("utf-8")) if username_buf else None),
            password=(SecretStr(password_buf.decode("utf-8")) if password_buf else SecretStr("")),
            url=SecretStr(url_buf.decode("utf-8")) if url_buf else None,
            notes=SecretStr(notes_buf.decode("utf-8")) if notes_buf else None,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
        )
    finally:
        for buf in (title_buf, password_buf, username_buf, url_buf, notes_buf):
            if buf is not None:
                zeroize_mutable_buffer(buf)


# ===========================================================================
# POST — Create
# ===========================================================================


@router.post(
    "/",
    response_model=EntryResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_entry(
    data: EntryCreateSchema,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> EntryResponseSchema:
    """Create a new encrypted password entry with a blind search index."""

    # Convert SecretStr → bytearray (all sensitive data)
    #
    # CRITICAL: We need TWO copies of the title — one for the blind index
    # (which gets zeroized by generate_search_index) and one for encryption
    # (which gets zeroized by encrypt_all_entry_fields).  This is the only
    # way to avoid a double-zeroize bug while keeping every buffer wiped.
    title_buf_for_index = _secret_to_bytearray(data.title)
    title_buf_for_enc = _secret_to_bytearray(data.title)
    password_buf = _secret_to_bytearray(data.password)
    username_buf = _secret_to_bytearray(data.username) if data.username else None
    url_buf = _secret_to_bytearray(data.url) if data.url else None
    notes_buf = _secret_to_bytearray(data.notes) if data.notes else None

    try:
        # 1. Blind index — zeroizes title_buf_for_index internally
        blind_index = generate_search_index(ctx.master_key, title_buf_for_index)

        # 2. Encrypt all fields — zeroizes title_buf_for_enc internally
        encrypted = encrypt_all_entry_fields(
            ctx.master_key,
            title=title_buf_for_enc,
            username=username_buf,
            password=password_buf,
            url=url_buf,
            notes=notes_buf,
        )
    finally:
        # Zeroize any buffers that survived encryption
        # (title_buf_for_index and title_buf_for_enc were already wiped inside their
        #  respective functions, but we zeroize again for defense-in-depth)
        for buf in (
            title_buf_for_index,
            title_buf_for_enc,
            password_buf,
            username_buf,
            url_buf,
            notes_buf,
        ):
            if buf is not None:
                zeroize_mutable_buffer(buf)

    entry = PasswordEntry(
        user_id=ctx.user_id,
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
    db.add(entry)
    await db.commit()
    await db.refresh(entry)

    # Return the freshly created entry decrypted for the response
    return _read_entry_response(entry, ctx.master_key)


# ===========================================================================
# GET (list) — List all non-deleted entries
# ===========================================================================


@router.get("/", response_model=list[EntryListItemSchema])
async def list_entries(
    query: Optional[str] = None,
    offset: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> list[EntryListItemSchema]:
    """List metadata for non-deleted entries (paginated).

    If *query* is provided, search by blind HMAC index — only matching titles
    are returned.  Passwords are **never** decrypted in this endpoint.
    """
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    if query:
        query_buf = bytearray(query.encode("utf-8"))
        try:
            search_hmac = generate_search_index(ctx.master_key, query_buf)
        finally:
            zeroize_mutable_buffer(query_buf)
        stmt = (
            select(PasswordEntry)
            .where(
                PasswordEntry.user_id == ctx.user_id,
                PasswordEntry.is_deleted == False,
                PasswordEntry.title_search == search_hmac,
            )
            .offset(offset)
            .limit(limit)
        )
        result = await db.execute(stmt)
        entries = list(result.scalars().all())
    else:
        stmt = (
            select(PasswordEntry)
            .where(
                PasswordEntry.user_id == ctx.user_id,
                PasswordEntry.is_deleted == False,
            )
            .offset(offset)
            .limit(limit)
        )
        result = await db.execute(stmt)
        entries = list(result.scalars().all())

    results: list[EntryListItemSchema] = []
    for entry in entries:
        title_locked: LockedBuffer | None = None
        url_locked: LockedBuffer | None = None
        try:
            # Decrypt title only
            title_locked = decrypt_entry_data(
                ctx.master_key,
                entry.title_cipher,
                entry.title_nonce,
            )
            title_str = _locked_to_str(title_locked)

            # Decrypt URL only if present
            url_str: Optional[str] = None
            if entry.url_cipher and entry.url_nonce:
                url_locked = decrypt_entry_data(
                    ctx.master_key,
                    entry.url_cipher,
                    entry.url_nonce,
                )
                url_str = _locked_to_str(url_locked)

            results.append(
                EntryListItemSchema(
                    id=entry.id,
                    title=SecretStr(title_str),
                    url=SecretStr(url_str) if url_str else None,
                )
            )
        finally:
            # Always close LockedBuffers to free non-pageable memory
            if title_locked is not None:
                title_locked.close()
            if url_locked is not None:
                url_locked.close()

    return results


# ===========================================================================
# E2EE Pass-Through API — encrypted envelopes only
# ===========================================================================


def _entry_service(db: AsyncSession) -> EntryService:
    return EntryService(db)


def _entry_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Entry not found or has been deleted",
    )


@router.post(
    "/e2ee",
    response_model=EntryEnvelopeResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_e2ee_entry(
    data: EntryEnvelopeCreateSchema,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> EntryEnvelopeResponseSchema:
    """Store a client-encrypted E2EE envelope without server-side crypto."""
    service = _entry_service(db)
    try:
        entry = await service.create_entry_async(ctx.user_id, data)
        return await service.get_entry_envelope_async(ctx.user_id, entry.id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid encrypted entry envelope",
        ) from exc


@router.get("/e2ee", response_model=list[EntryEnvelopeResponseSchema])
async def list_e2ee_entries(
    query: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> list[EntryEnvelopeResponseSchema]:
    """List client-encrypted E2EE envelopes."""
    service = _entry_service(db)
    entries = (
        await service.search_entries_async(ctx.user_id, query)
        if query
        else await service.list_entries_async(ctx.user_id)
    )

    result: list[EntryEnvelopeResponseSchema] = []
    for entry in entries:
        try:
            result.append(service.to_envelope_response(entry))
        except EntryNotFoundError:
            continue
    return result


@router.get("/e2ee/{entry_id}", response_model=EntryEnvelopeResponseSchema)
async def read_e2ee_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> EntryEnvelopeResponseSchema:
    """Return one encrypted E2EE envelope without decrypting it."""
    try:
        return await _entry_service(db).get_entry_envelope_async(ctx.user_id, entry_id)
    except EntryNotFoundError as exc:
        raise _entry_not_found() from exc


@router.patch("/e2ee/{entry_id}", response_model=EntryEnvelopeResponseSchema)
async def update_e2ee_entry(
    entry_id: int,
    data: EntryEnvelopeUpdateSchema,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> EntryEnvelopeResponseSchema:
    """Replace or update metadata for a client-encrypted E2EE envelope."""
    service = _entry_service(db)
    try:
        await service.update_entry_async(ctx.user_id, entry_id, data)
        return await service.get_entry_envelope_async(ctx.user_id, entry_id)
    except EntryNotFoundError as exc:
        raise _entry_not_found() from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid encrypted entry envelope",
        ) from exc


@router.delete("/e2ee/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_e2ee_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> None:
    """Soft-delete an E2EE envelope."""
    try:
        await _entry_service(db).delete_entry_async(ctx.user_id, entry_id)
    except EntryNotFoundError as exc:
        raise _entry_not_found() from exc


# ===========================================================================
# GET (single) — Read one entry
# ===========================================================================


@router.get("/{entry_id}", response_model=EntryResponseSchema)
async def read_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> EntryResponseSchema:
    """Read a single entry with all fields decrypted."""
    entry = await _fetch_active_entry(db, entry_id, ctx.user_id)
    return _read_entry_response(entry, ctx.master_key)


# ===========================================================================
# PATCH — Update (with optimistic concurrency control)
# ===========================================================================


@router.patch("/{entry_id}", response_model=EntryResponseSchema)
async def update_entry(
    entry_id: int,
    data: EntryUpdateSchema,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> EntryResponseSchema:
    """Partially update an entry.

    * Only fields explicitly set in the request are re-encrypted.
    * If the title changes, the blind search index is regenerated.
    * If the password changes, the old encrypted password is archived to
      ``PasswordHistory`` (cipher/nonce copied directly — same master key).
    * Optimistic concurrency via ``version_id`` — stale updates return 409.
    """
    entry = await _fetch_active_entry(db, entry_id, ctx.user_id)

    update_dict = data.model_dump(exclude_unset=True)
    if not update_dict:
        # Nothing to change — return current state
        return _read_entry_response(entry, ctx.master_key)

    # --- Password history: snapshot old password before replacement ---
    if "password" in update_dict and data.password is not None:
        history = PasswordHistory(
            entry_id=entry.id,
            password_cipher=entry.password_cipher,
            password_nonce=entry.password_nonce,
            reason="Password update via API",
        )
        db.add(history)

    # --- Re-encrypt only changed fields ---
    for field_name in ("title", "username", "password", "url", "notes"):
        new_value = getattr(data, field_name, None)

        if new_value is not None:
            buf = _secret_to_bytearray(new_value)
            try:
                cipher_hex, nonce_hex = _encrypt_field_to_hex(ctx.master_key, buf)
            finally:
                zeroize_mutable_buffer(buf)

            setattr(entry, f"{field_name}_cipher", cipher_hex)
            setattr(entry, f"{field_name}_nonce", nonce_hex)

            # Regenerate blind index when title changes
            if field_name == "title":
                title_buf_for_index = _secret_to_bytearray(new_value)
                try:
                    entry.title_search = generate_search_index(
                        ctx.master_key,
                        title_buf_for_index,
                    )
                finally:
                    zeroize_mutable_buffer(title_buf_for_index)
        else:
            # Explicitly nullify optional fields (never title or password)
            if field_name not in ("title", "password"):
                setattr(entry, f"{field_name}_cipher", None)
                setattr(entry, f"{field_name}_nonce", None)

    # --- Commit with optimistic concurrency guard ---
    try:
        await db.flush()
        await db.commit()
    except StaleDataError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Conflict: Stale Data — entry was modified concurrently",
        ) from exc

    await db.refresh(entry)
    return _read_entry_response(entry, ctx.master_key)


# ===========================================================================
# GET — Password History
# ===========================================================================


@router.get(
    "/{entry_id}/history",
    response_model=list[HistoryResponseSchema],
    summary="История паролей записи",
)
async def get_entry_history(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> list[HistoryResponseSchema]:
    """
    Возвращает архив старых паролей записи.

    Каждый пароль расшифровывается через реальный крипто-пайплайн,
    plaintext немедленно обнуляется (Zero-Trust).
    """
    from backend.features.password_history_manager import PasswordHistoryManager

    # Verify entry belongs to user and is not deleted
    entry = await _fetch_active_entry(db, entry_id, ctx.user_id)

    history_mgr = PasswordHistoryManager(db)
    return await history_mgr.get_history_async(entry.id, ctx.master_key)


# ===========================================================================
# DELETE — Soft delete (move to trash)
# ===========================================================================


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> None:
    """Soft-delete an entry (sets ``is_deleted=True``)."""
    entry = await _fetch_active_entry(db, entry_id, ctx.user_id)
    entry.is_deleted = True
    entry.deleted_at = datetime.now(timezone.utc)
    await db.commit()


# ===========================================================================
# Low-level crypto helpers (local to this module)
# ===========================================================================


def _encrypt_field_to_hex(
    key: LockedBuffer,
    plaintext_buf: bytearray,
) -> tuple[str, str]:
    """Encrypt a single ``bytearray`` field and return (cipher_hex, nonce_hex)."""
    return encrypt_entry_data(key, plaintext_buf)
