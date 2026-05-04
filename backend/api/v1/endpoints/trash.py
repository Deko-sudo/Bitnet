# -*- coding: utf-8 -*-
"""
Trash API Router — управление корзиной (Soft Delete Management).

Позволяет просматривать скрытые записи, восстанавливать их или
уничтожать полностью.  Все операции асинхронны через ``AsyncSession``.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.v1.endpoints.auth import CryptoContext, get_current_user
from backend.core.crypto_bridge import LockedBuffer, zeroize_mutable_buffer
from backend.core.encryption_helper import decrypt_entry_data
from backend.database.models import PasswordEntry
from backend.database.schemas import EntryListItemSchema
from backend.database.session import get_db

router = APIRouter()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _locked_to_str(locked: LockedBuffer) -> str:
    buf = bytearray(len(locked))
    locked.copy_into(buf)
    try:
        return buf.decode("utf-8")
    finally:
        zeroize_mutable_buffer(buf)


async def _fetch_deleted_entry(
    db: AsyncSession, entry_id: int, user_id: int
) -> PasswordEntry:
    """Return a deleted entry owned by *user_id*, or raise 404."""
    stmt = select(PasswordEntry).where(
        PasswordEntry.id == entry_id,
        PasswordEntry.user_id == user_id,
        PasswordEntry.is_deleted == True,  # noqa: E712
    )
    result = await db.execute(stmt)
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found in trash.")
    return entry


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/", response_model=list[EntryListItemSchema])
async def list_trash(
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> list[EntryListItemSchema]:
    """Список записей в корзине (пароли НЕ расшифровываются)."""
    stmt = select(PasswordEntry).where(
        PasswordEntry.user_id == ctx.user_id,
        PasswordEntry.is_deleted == True,  # noqa: E712
    )
    result = await db.execute(stmt)
    entries = list(result.scalars().all())

    results: list[EntryListItemSchema] = []
    for entry in entries:
        title_locked: LockedBuffer | None = None
        url_locked: LockedBuffer | None = None
        try:
            title_locked = decrypt_entry_data(
                ctx.master_key, entry.title_cipher, entry.title_nonce
            )
            title_str = _locked_to_str(title_locked)

            url_str: Optional[str] = None
            if entry.url_cipher and entry.url_nonce:
                url_locked = decrypt_entry_data(
                    ctx.master_key, entry.url_cipher, entry.url_nonce
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
            if title_locked is not None:
                title_locked.close()
            if url_locked is not None:
                url_locked.close()

    return results


@router.post("/{entry_id}/restore", status_code=status.HTTP_200_OK)
async def restore_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> dict[str, str]:
    """Восстанавливает запись из корзины."""
    entry = await _fetch_deleted_entry(db, entry_id, ctx.user_id)

    entry.is_deleted = False
    entry.deleted_at = None
    await db.commit()
    return {"message": "Entry successfully restored from trash."}


@router.delete("/{entry_id}/purge", status_code=status.HTTP_204_NO_CONTENT)
async def purge_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> None:
    """Физическое уничтожение записи из БД (навсегда)."""
    entry = await _fetch_deleted_entry(db, entry_id, ctx.user_id)

    await db.delete(entry)
    await db.commit()
