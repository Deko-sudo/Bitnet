# -*- coding: utf-8 -*-
"""
Import/Export API — Async streaming endpoints for data portability.

* Import: принимает CSV или JSONL, валидирует через Pydantic, шифрует
  и вставляет батчами.
* Export: StreamingResponse — данные отдаются построчно через async
  generator, без загрузки всего набора в RAM.
"""

from __future__ import annotations

from typing import AsyncGenerator

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.v1.endpoints.auth import CryptoContext, get_current_user
from backend.database.session import get_db
from backend.services.import_export import (
    DataPortabilityService,
    ImportDatabaseError,
    ImportResult,
)

router = APIRouter()


# ===========================================================================
# Dependency: создать сервис с master_key из контекста
# ===========================================================================


def _get_portability_service(
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> DataPortabilityService:
    """Inject DataPortabilityService с AsyncSession и мастер-ключом пользователя."""
    return DataPortabilityService(
        session=db,
        master_key=ctx.master_key,
    )


# ===========================================================================
# POST /import/csv — Импорт из CSV
# ===========================================================================


@router.post(
    "/import/csv",
    response_model=ImportResult,
    status_code=status.HTTP_200_OK,
    summary="Импорт паролей из CSV",
)
async def import_csv(
    file: UploadFile = File(
        ...,
        description="CSV-файл с колонками: title, username, password, url, notes",
    ),
    ctx: CryptoContext = Depends(get_current_user),
    service: DataPortabilityService = Depends(_get_portability_service),
) -> ImportResult:
    """
    Загрузить CSV-файл с паролями.

    **Формат CSV**:
    ```
    title,username,password,url,notes
    Google,user@gmail.com,supersecret123,https://google.com,Main account
    ```

    Возвращает статистику: сколько записей импортировано, пропущено, ошибок.
    """
    if not file.content_type or "csv" not in file.content_type.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content-Type must be text/csv",
        )

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File is empty",
        )

    try:
        result = await service.import_from_csv(ctx.user_id, content)
    except ImportDatabaseError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database error during import: {exc}",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected database error: {exc}",
        ) from exc

    return result


# ===========================================================================
# POST /import/jsonl — Импорт из JSONL
# ===========================================================================


@router.post(
    "/import/jsonl",
    response_model=ImportResult,
    status_code=status.HTTP_200_OK,
    summary="Импорт паролей из JSONL",
)
async def import_jsonl(
    file: UploadFile = File(
        ...,
        description="JSONL-файл (одна JSON-запись на строку)",
    ),
    ctx: CryptoContext = Depends(get_current_user),
    service: DataPortabilityService = Depends(_get_portability_service),
) -> ImportResult:
    """
    Загрузить JSONL-файл с паролями.

    **Формат JSONL** (одна строка = один объект):
    ```
    {"title": "Google", "username": "user@gmail.com", "password": "supersecret"}
    {"title": "GitHub", "password": "gh_token_123"}
    ```
    """
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File is empty",
        )

    try:
        result = await service.import_from_jsonl(ctx.user_id, content)
    except ImportDatabaseError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database error during import: {exc}",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected database error: {exc}",
        ) from exc

    return result


# ===========================================================================
# GET /export/csv — Streaming CSV-экспорт
# ===========================================================================


@router.get(
    "/export/csv",
    response_class=StreamingResponse,
    summary="Экспорт в CSV (streaming)",
)
async def export_csv(
    ctx: CryptoContext = Depends(get_current_user),
    service: DataPortabilityService = Depends(_get_portability_service),
) -> StreamingResponse:
    """
    Экспортировать все парои пользователя в CSV.

    **Streaming**: данные отдаются построчно, без загрузки всего набора в RAM.
    Подходит для больших наборов данных (10 000+ записей).

    **Внимание**: ответ содержит расшифрованные пароли — передавайте только
    по HTTPS.
    """

    async def csv_generator() -> AsyncGenerator[bytes, None]:
        async for chunk in service.export_to_csv_stream(ctx.user_id):
            yield chunk.encode("utf-8")

    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="bitnet_export.csv"',
            "X-Accel-Buffering": "no",  # Отключить буферизацию в reverse proxy
        },
    )


# ===========================================================================
# GET /export/jsonl — Streaming JSONL-экспорт
# ===========================================================================


@router.get(
    "/export/jsonl",
    response_class=StreamingResponse,
    summary="Экспорт в JSONL (streaming)",
)
async def export_jsonl(
    ctx: CryptoContext = Depends(get_current_user),
    service: DataPortabilityService = Depends(_get_portability_service),
) -> StreamingResponse:
    """
    Экспортировать все пароли пользователя в JSONL.

    **Streaming**: данные отдаются построчно (один JSON-объект на строку).
    Формат удобен для парсинга и импорта обратно.
    """

    async def jsonl_generator() -> AsyncGenerator[bytes, None]:
        async for chunk in service.export_to_jsonl_stream(ctx.user_id):
            yield chunk.encode("utf-8")

    return StreamingResponse(
        jsonl_generator(),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": 'attachment; filename="bitnet_export.jsonl"',
            "X-Accel-Buffering": "no",
        },
    )
