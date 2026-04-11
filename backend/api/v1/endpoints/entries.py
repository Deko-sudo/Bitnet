# -*- coding: utf-8 -*-
"""
Entries API Router - Реализация CRUD слоя контроллеров REST.
Содержит 100% покрытие Zero-Trust концепции: минимизация расшифровок (RAM).
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import SecretStr

from backend.database.session import get_db
from backend.database.schemas import EntryCreateSchema, EntryUpdateSchema, EntryResponseSchema, EntryListItemSchema
from backend.database.entry_service import EntryService, EntryNotFoundError
from backend.features.search_engine import SearchService
from backend.core.encryption_helper import EncryptionHelper
from backend.core.crypto_core import zero_memory
from backend.database.models import PasswordEntry

router = APIRouter()

# --- ПОРОК АРХИТЕКТУРЫ: КОНТЕКСТ ПОЛЬЗОВАТЕЛЯ ---
def get_user_context() -> tuple[int, EncryptionHelper]:
    """
    Заглушка (Mock) для Dependency Injection (DI).
    
    Мехника (Провал в продакшене):
    1. Роутер извлекает JWT из Authorization Header или HTTP-only cookie.
    2. По субьекту токена мы находим `user_id`. (Осуществляется через AuthManager).
    3. Мы достаем **эфемерный мастер-ключ** из пула памяти AuthManager Никиты, 
       который разблокирован пользователем на время сессии 15 мин (in-memory redis/dict).
    4. Оборачиваем ключ в EncryptionHelper.
    """
    mock_user_id = 1
    # Эмулируем ключ 32 байта для EncryptionHelper (обычно это делегируется в AuthManager)
    def key_provider() -> bytearray:
        return bytearray(b"0" * 32)
    return mock_user_id, EncryptionHelper(key_provider=key_provider)


@router.post("/", response_model=EntryResponseSchema, status_code=status.HTTP_201_CREATED)
def create_entry(
    data: EntryCreateSchema,
    db: Session = Depends(get_db),
    context: tuple[int, EncryptionHelper] = Depends(get_user_context)
):
    """Создает защищенную запись. Слепой индекс генерируется автоматически."""
    user_id, helper = context
    service = EntryService(db, helper)
    # create_entry инкапсулирует save и обнуление RAM
    new_entry = service.create_entry(user_id, data)
    # Функция get_entry безопасно расшифровывает созданную запись для ответа (c `finally:` zero_memory)
    return service.get_entry(user_id, new_entry.id)


@router.get("/{entry_id}", response_model=EntryResponseSchema)
def read_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    context: tuple[int, EncryptionHelper] = Depends(get_user_context)
):
    """Чтение ОДНОЙ записи. Здесь пароль расшифровывается в SecretStr."""
    user_id, helper = context
    service = EntryService(db, helper)
    try:
        return service.get_entry(user_id, entry_id)
    except EntryNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.patch("/{entry_id}", response_model=EntryResponseSchema)
def update_entry(
    entry_id: int,
    data: EntryUpdateSchema,
    db: Session = Depends(get_db),
    context: tuple[int, EncryptionHelper] = Depends(get_user_context)
):
    """Частичное редактирование (PATCH). Интегрировано создание истории старых паролей."""
    user_id, helper = context
    service = EntryService(db, helper)
    try:
        service.update_entry(user_id, entry_id, data)
        return service.get_entry(user_id, entry_id)
    except EntryNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    context: tuple[int, EncryptionHelper] = Depends(get_user_context)
):
    """Мягкое перемещение в корзину."""
    user_id, helper = context
    service = EntryService(db, helper)
    try:
        service.soft_delete_entry(user_id, entry_id)
    except EntryNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/", response_model=List[EntryListItemSchema])
def list_entries(
    query: str = None, 
    db: Session = Depends(get_db), 
    context: tuple[int, EncryptionHelper] = Depends(get_user_context)
):
    """
    Вывод списка. Архитектура Zero-Trust:
    1. Исключает расшифровку passwords.
    2. Включает механизм поиска по Blind Index при передаче query (Сложность поиска - О(n)).
    """
    user_id, helper = context
    
    if query:
        search_svc = SearchService(db, helper)
        entries = search_svc.search_by_title(user_id, query)
    else:
        entries = db.query(PasswordEntry).filter(
            PasswordEntry.user_id == user_id,
            PasswordEntry.is_deleted == False
        ).all()
        
    results = []
    # Забираем мастер-ключ единожды для всего батча записей
    with helper._operation_key() as key:
        for e in entries:
            try:
                # Дешифровка Title
                title_b = helper._decrypt_text_field(e.title_cipher, e.title_nonce, key)
                title_sec = SecretStr(title_b.decode('utf-8'))
                zero_memory(title_b)  # Принудительная очистка RAM (C-уровень)
                
                # Дешифровка URL (Опционально)
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
                # В случае битого ключа пропускаем запись
                pass
                
    return results
