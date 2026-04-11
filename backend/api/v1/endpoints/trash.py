# -*- coding: utf-8 -*-
"""
Trash API Router - Управление корзиной (Soft Delete Management).
Позволяет просматривать скрытые записи, восстанавливать их или уничтожать полностью.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import SecretStr

from backend.database.session import get_db
from backend.api.v1.endpoints.entries import get_user_context
from backend.database.schemas import EntryListItemSchema
from backend.core.encryption_helper import EncryptionHelper
from backend.database.models import PasswordEntry
from backend.core.crypto_core import zero_memory

router = APIRouter()

@router.get("/", response_model=List[EntryListItemSchema])
def list_trash(
    db: Session = Depends(get_db), 
    context: tuple[int, EncryptionHelper] = Depends(get_user_context)
):
    """
    Выводит список записей в корзине.
    В соответствии с Zero-Trust для `list_entries`, пароли НЕ расшифровываются.
    """
    user_id, helper = context
    entries = db.query(PasswordEntry).filter(
        PasswordEntry.user_id == user_id,
        PasswordEntry.is_deleted == True
    ).all()
        
    results = []
    # Контекст-ключик запрашивается один раз на запрос
    with helper._operation_key() as key:
        for e in entries:
            try:
                title_b = helper._decrypt_text_field(e.title_cipher, e.title_nonce, key)
                title_sec = SecretStr(title_b.decode('utf-8'))
                zero_memory(title_b)
                
                url_sec = None
                if e.url_cipher:
                    url_b = helper._decrypt_text_field(e.url_cipher, e.url_nonce, key)
                    url_sec = SecretStr(url_b.decode('utf-8'))
                    zero_memory(url_b)

                results.append(EntryListItemSchema(
                    id=e.id,
                    title=title_sec,
                    url=url_sec
                ))
            except Exception:
                pass
                
    return results

@router.post("/{entry_id}/restore", status_code=status.HTTP_200_OK)
def restore_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    context: tuple[int, EncryptionHelper] = Depends(get_user_context)
):
    """Восстанавливает запись из корзины (убирает флаг is_deleted)."""
    user_id, helper = context
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.id == entry_id,
        PasswordEntry.user_id == user_id,
        PasswordEntry.is_deleted == True
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found in trash.")

    entry.is_deleted = False
    entry.deleted_at = None
    db.commit()
    return {"message": "Entry successfully restored from trash."}

@router.delete("/{entry_id}/purge", status_code=status.HTTP_204_NO_CONTENT)
def purge_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    context: tuple[int, EncryptionHelper] = Depends(get_user_context)
):
    """
    Физическое уничтожение записи из БД (Purge).
    Удаляется навсегда (включая привязанную историю, если настроен CASCADE в СУБД).
    """
    user_id, helper = context
    entry = db.query(PasswordEntry).filter(
        PasswordEntry.id == entry_id,
        PasswordEntry.user_id == user_id,
        PasswordEntry.is_deleted == True
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found in trash.")

    db.delete(entry)
    db.commit()
