# -*- coding: utf-8 -*-
"""
Backup Manager API endpoints — Zero-Trust encrypted backup / restore.

Every endpoint requires authentication (``get_current_user`` dependency).
Restore demands ``confirmed=True`` to prevent accidental data loss.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.v1.endpoints.auth import CryptoContext, get_current_user
from backend.database.session import get_db
from backend.features.backup_manager import BackupError, BackupManager

router = APIRouter()


class BackupInfoResponse(BaseModel):
    """Public metadata for a stored backup file."""

    name: str
    size_bytes: int
    created_at: str


class BackupCreateResponse(BaseModel):
    """Response after a successful backup creation."""

    message: str


class BackupRestoreRequest(BaseModel):
    """Request body for restore operation."""

    confirmed: bool = False


class BackupRestoreResponse(BaseModel):
    """Response after a successful restore."""

    restored_count: int
    message: str


# ---------------------------------------------------------------------------
# POST /api/v1/backups — Create
# ---------------------------------------------------------------------------

@router.post(
    "/",
    response_model=BackupCreateResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Backups"],
)
async def create_backup(
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> BackupCreateResponse:
    """Encrypt all active entries and write a backup file."""
    mgr = BackupManager(db)
    try:
        path: Path = await mgr.create(ctx.user_id, ctx.master_key)
    except BackupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return BackupCreateResponse(
        message="Backup created successfully",
    )


# ---------------------------------------------------------------------------
# GET /api/v1/backups — List
# ---------------------------------------------------------------------------

@router.get("/", response_model=list[BackupInfoResponse], tags=["Backups"])
async def list_backups(
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> list[BackupInfoResponse]:
    """Return metadata for every backup belonging to the authenticated user."""
    mgr = BackupManager(db)
    infos = await mgr.list(ctx.user_id)
    return [
        BackupInfoResponse(
            name=info.name,
            size_bytes=info.size_bytes,
            created_at=info.created_at.isoformat(),
        )
        for info in infos
    ]


# ---------------------------------------------------------------------------
# POST /api/v1/backups/{name}/restore — Restore
# ---------------------------------------------------------------------------

@router.post(
    "/{backup_name}/restore",
    response_model=BackupRestoreResponse,
    tags=["Backups"],
)
async def restore_backup(
    backup_name: str,
    request: BackupRestoreRequest,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> BackupRestoreResponse:
    """
    Restore entries from a backup file.

    *confirmed* MUST be ``True`` or the operation is refused.
    """
    mgr = BackupManager(db)
    try:
        count = await mgr.restore(
            ctx.user_id,
            ctx.master_key,
            backup_name,
            confirmed=request.confirmed,
        )
    except BackupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return BackupRestoreResponse(
        restored_count=count,
        message=f"Restored {count} entries from {backup_name}",
    )


# ---------------------------------------------------------------------------
# POST /api/v1/backups/rotate — Manual rotation
# ---------------------------------------------------------------------------

@router.post("/rotate", tags=["Backups"])
async def rotate_backups(
    max_backups: int = 10,
    db: AsyncSession = Depends(get_db),
    ctx: CryptoContext = Depends(get_current_user),
) -> dict[str, Any]:
    """Delete oldest backups exceeding *max_backups*."""
    if max_backups < 1:
        max_backups = 1
    if max_backups > 100:
        max_backups = 100
    mgr = BackupManager(db)
    removed = await mgr.rotate(ctx.user_id, max_backups=max_backups)
    return {"removed": removed, "message": f"Removed {removed} old backups"}
