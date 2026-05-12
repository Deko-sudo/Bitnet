# -*- coding: utf-8 -*-
"""
Breach Monitor API endpoints.

REST API for monitoring passwords and emails against HIBP breaches.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.models import BreachAlert
from backend.database.session import get_db
from backend.api.v1.endpoints.auth import get_current_user, CryptoContext
from backend.core.advanced_security import HaveIBeenPwnedChecker
from backend.core.security_utils import RateLimiter
from backend.features.breach_monitor_async import AsyncBreachMonitorService

router = APIRouter()

_breach_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60, block_duration_seconds=300)


class MonitorPasswordRequest(BaseModel):
    password: SecretStr


class MonitorEmailRequest(BaseModel):
    email: EmailStr


class AlertAcknowledgeResponse(BaseModel):
    alert_id: str
    status: str


class BreachStatusResponse(BaseModel):
    monitored_items: int
    unacknowledged_alerts: int
    running: bool


async def get_breach_monitor(request: Request) -> AsyncBreachMonitorService:
    monitor: Optional[AsyncBreachMonitorService] = getattr(
        request.app.state, "breach_monitor", None
    )
    if monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Breach monitor service not available",
        )
    return monitor


@router.get("/status", response_model=BreachStatusResponse)
async def breach_status(
    user: CryptoContext = Depends(get_current_user),
    monitor: AsyncBreachMonitorService = Depends(get_breach_monitor),
):
    status_data = await monitor.get_status(user.user_id)
    return BreachStatusResponse(**status_data)


@router.post("/monitor/password", status_code=status.HTTP_201_CREATED)
async def add_password(
    req: MonitorPasswordRequest,
    user: CryptoContext = Depends(get_current_user),
    monitor: AsyncBreachMonitorService = Depends(get_breach_monitor),
):
    item_id = await monitor.add_password(user.user_id, req.password.get_secret_value())
    return {"item_id": item_id, "status": "monitoring"}


@router.post("/monitor/email", status_code=status.HTTP_201_CREATED)
async def add_email(
    req: MonitorEmailRequest,
    user: CryptoContext = Depends(get_current_user),
    monitor: AsyncBreachMonitorService = Depends(get_breach_monitor),
):
    item_id = await monitor.add_email(user.user_id, req.email)
    return {"item_id": item_id, "status": "monitoring"}


@router.delete("/monitor/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_item(
    item_id: str,
    user: CryptoContext = Depends(get_current_user),
    monitor: AsyncBreachMonitorService = Depends(get_breach_monitor),
):
    removed = await monitor.remove_item(item_id, user.user_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Item not found")


@router.get("/alerts")
async def list_alerts(
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    user: CryptoContext = Depends(get_current_user),
    monitor: AsyncBreachMonitorService = Depends(get_breach_monitor),
):
    alerts = await monitor.get_alerts(
        user.user_id,
        severity=severity,
        status=status_filter,
    )
    return [
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "value_preview": a.value_preview,
            "breach_count": a.breach_count,
            "severity": a.severity,
            "status": a.status,
            "detected_at": a.detected_at.isoformat() if a.detected_at else None,
        }
        for a in alerts
    ]


@router.patch("/alerts/{alert_id}/acknowledge", response_model=AlertAcknowledgeResponse)
async def acknowledge_alert(
    alert_id: str,
    user: CryptoContext = Depends(get_current_user),
    monitor: AsyncBreachMonitorService = Depends(get_breach_monitor),
):
    alert = await monitor.acknowledge_alert(alert_id, user.user_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertAcknowledgeResponse(alert_id=alert.id, status="acknowledged")


@router.patch("/alerts/{alert_id}/resolve", response_model=AlertAcknowledgeResponse)
async def resolve_alert(
    alert_id: str,
    user: CryptoContext = Depends(get_current_user),
    monitor: AsyncBreachMonitorService = Depends(get_breach_monitor),
):
    alert = await monitor.resolve_alert(alert_id, user.user_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertAcknowledgeResponse(alert_id=alert.id, status="resolved")


@router.post("/check/password")
async def check_password_now(
    req: MonitorPasswordRequest,
    user: CryptoContext = Depends(get_current_user),
):
    rate_key = f"breach-pw:{user.user_id}"
    if not _breach_rate_limiter.can_attempt(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many breach check requests. Please try again later.",
        )
    async with HaveIBeenPwnedChecker() as checker:
        is_pwned, count = await checker.check_password(req.password.get_secret_value())
    _breach_rate_limiter.register_success(rate_key)
    return {"is_pwned": is_pwned, "breach_count": count}


@router.post("/check/email")
async def check_email_now(
    req: MonitorEmailRequest,
    user: CryptoContext = Depends(get_current_user),
):
    rate_key = f"breach-email:{user.user_id}"
    if not _breach_rate_limiter.can_attempt(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many breach check requests. Please try again later.",
        )
    async with HaveIBeenPwnedChecker() as checker:
        try:
            is_pwned, count = await checker.check_email(req.email)
        except PermissionError:
            _breach_rate_limiter.register_failed(rate_key)
            raise HTTPException(
                status_code=403,
                detail="HIBP API key required for email checks",
            )
        except ConnectionError as exc:
            _breach_rate_limiter.register_failed(rate_key)
            raise HTTPException(status_code=502, detail="Breach check service unavailable")
    _breach_rate_limiter.register_success(rate_key)
    return {"is_pwned": is_pwned, "breach_count": count}


@router.post("/check/now")
async def trigger_check_now(
    user: CryptoContext = Depends(get_current_user),
    monitor: AsyncBreachMonitorService = Depends(get_breach_monitor),
):
    checked = await monitor.check_now(user_id=user.user_id)
    return {"checked_items": checked, "status": "completed"}