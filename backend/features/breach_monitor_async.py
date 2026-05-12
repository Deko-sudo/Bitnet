# -*- coding: utf-8 -*-
"""
Async Breach Monitor Service

Fully asyncio-based breach monitoring that persists state in SQLAlchemy
instead of JSON files and uses no threading.

- All DB operations are async via ``AsyncSession``.
- Plaintext emails are held in ``_runtime_emails`` (in-memory only).
- Passwords are stored as SHA-1 k-anonymity prefixes (5-char).
- The background monitor loop uses ``asyncio.create_task`` + ``asyncio.sleep``.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from sqlalchemy import func as sa_func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.advanced_security import HaveIBeenPwnedChecker
from backend.database.models import BreachAlert, MonitoredItem


logger = logging.getLogger(__name__)


def _severity(breach_count: int) -> str:
    if breach_count > 1_000_000:
        return "critical"
    if breach_count > 10_000:
        return "high"
    if breach_count > 100:
        return "medium"
    return "low"


class AsyncBreachMonitorService:
    """Async breach monitor backed by SQLAlchemy (no JSON, no threads)."""

    def __init__(
        self,
        db_session_factory: Callable[[], AsyncSession],
        *,
        check_interval_hours: int = 24,
        hibp_api_key: Optional[str] = None,
    ) -> None:
        self._db_session_factory = db_session_factory
        self._check_interval = check_interval_hours * 3600
        self._hibp_api_key = hibp_api_key
        self._checker: Optional[HaveIBeenPwnedChecker] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._runtime_emails: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._checker = HaveIBeenPwnedChecker(api_key=self._hibp_api_key)
        await self._checker._get_client()
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("AsyncBreachMonitorService started")

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._checker is not None:
            await self._checker.close()
            self._checker = None
        logger.info("AsyncBreachMonitorService stopped")

    @property
    def running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Item management
    # ------------------------------------------------------------------

    async def add_password(self, user_id: int, password: str) -> str:
        sha1_hash = hashlib.sha1(
            password.encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest().upper()

        async with self._db_session_factory() as db:
            existing = await db.scalar(
                select(MonitoredItem).where(
                    MonitoredItem.user_id == user_id,
                    MonitoredItem.item_type == "password",
                    MonitoredItem.value_hash == sha1_hash,
                    MonitoredItem.is_active == True,
                )
            )
            if existing:
                return existing.id

            item_id = secrets.token_urlsafe(16)
            item = MonitoredItem(
                id=item_id,
                user_id=user_id,
                item_type="password",
                value_hash=sha1_hash,
            )
            db.add(item)
            await db.commit()
            return item_id

    async def add_email(self, user_id: int, email: str) -> str:
        normalized = email.strip().lower()
        email_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        async with self._db_session_factory() as db:
            existing = await db.scalar(
                select(MonitoredItem).where(
                    MonitoredItem.user_id == user_id,
                    MonitoredItem.item_type == "email",
                    MonitoredItem.value_hash == email_hash,
                    MonitoredItem.is_active == True,
                )
            )
            if existing:
                self._runtime_emails[existing.id] = normalized
                return existing.id

            item_id = secrets.token_urlsafe(16)
            item = MonitoredItem(
                id=item_id,
                user_id=user_id,
                item_type="email",
                value_hash=email_hash,
            )
            db.add(item)
            await db.commit()
            self._runtime_emails[item_id] = normalized
            return item_id

    async def remove_item(self, item_id: str, user_id: int) -> bool:
        async with self._db_session_factory() as db:
            result = await db.scalar(
                select(MonitoredItem).where(
                    MonitoredItem.id == item_id,
                    MonitoredItem.user_id == user_id,
                )
            )
            if result is None:
                return False
            result.is_active = False
            await db.commit()
            self._runtime_emails.pop(item_id, None)
            return True

    async def get_user_items(self, user_id: int) -> List[MonitoredItem]:
        async with self._db_session_factory() as db:
            result = await db.execute(
                select(MonitoredItem).where(
                    MonitoredItem.user_id == user_id,
                    MonitoredItem.is_active == True,
                )
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    async def get_alerts(
        self,
        user_id: int,
        *,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[BreachAlert]:
        async with self._db_session_factory() as db:
            query = select(BreachAlert).where(BreachAlert.user_id == user_id)
            if severity:
                query = query.where(BreachAlert.severity == severity)
            if status:
                query = query.where(BreachAlert.status == status)
            query = query.order_by(BreachAlert.detected_at.desc()).limit(limit)
            result = await db.execute(query)
            return list(result.scalars().all())

    async def acknowledge_alert(self, alert_id: str, user_id: int) -> Optional[BreachAlert]:
        async with self._db_session_factory() as db:
            alert = await db.scalar(
                select(BreachAlert).where(
                    BreachAlert.id == alert_id,
                    BreachAlert.user_id == user_id,
                )
            )
            if alert is None:
                return None
            alert.status = "acknowledged"
            alert.acknowledged_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(alert)
            return alert

    async def resolve_alert(self, alert_id: str, user_id: int) -> Optional[BreachAlert]:
        async with self._db_session_factory() as db:
            alert = await db.scalar(
                select(BreachAlert).where(
                    BreachAlert.id == alert_id,
                    BreachAlert.user_id == user_id,
                )
            )
            if alert is None:
                return None
            alert.status = "resolved"
            alert.resolved_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(alert)
            return alert

    # ------------------------------------------------------------------
    # On-demand check
    # ------------------------------------------------------------------

    async def check_now(self, user_id: Optional[int] = None) -> int:
        async with self._db_session_factory() as db:
            query = select(MonitoredItem).where(MonitoredItem.is_active == True)
            if user_id is not None:
                query = query.where(MonitoredItem.user_id == user_id)
            result = await db.execute(query)
            items = list(result.scalars().all())

        checked = 0
        for item in items:
            try:
                await self._check_item(item)
                checked += 1
            except Exception as exc:
                logger.exception(
                    "[AsyncBreachMonitor] check error item_id=%s: %s", item.id, exc
                )
        return checked

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    async def _monitor_loop(self) -> None:
        while self._running:
            try:
                await self.check_now()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception("[AsyncBreachMonitor] monitor loop error: %s", exc)
            if self._running:
                await asyncio.sleep(self._check_interval)

    async def _check_item(self, item: MonitoredItem) -> None:
        if self._checker is None:
            return

        is_pwned = False
        breach_count = 0

        if item.item_type == "password":
            sha1_hash = item.value_hash
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            is_pwned, breach_count = await self._checker.check_suffix(prefix, suffix)
        elif item.item_type == "email":
            email = self._runtime_emails.get(item.id)
            if email is None:
                logger.warning(
                    "[AsyncBreachMonitor] email not resolvable for item_id=%s",
                    item.id,
                )
                return
            is_pwned, breach_count = await self._checker.check_email(email)
        else:
            return

        async with self._db_session_factory() as db:
            db_item = await db.scalar(
                select(MonitoredItem).where(MonitoredItem.id == item.id)
            )
            if db_item:
                db_item.last_checked = datetime.now(timezone.utc)
                db_item.check_count = (db_item.check_count or 0) + 1
                await db.commit()

        if is_pwned and breach_count > 0:
            await self._create_alert(item, breach_count)

    async def _create_alert(self, item: MonitoredItem, breach_count: int) -> None:
        severity = _severity(breach_count)
        alert_id = secrets.token_urlsafe(16)

        async with self._db_session_factory() as db:
            existing = await db.scalar(
                select(BreachAlert).where(
                    BreachAlert.user_id == item.user_id,
                    BreachAlert.value_hash == item.value_hash,
                    BreachAlert.status == "new",
                )
            )
            if existing:
                return

            alert = BreachAlert(
                id=alert_id,
                user_id=item.user_id,
                alert_type=item.item_type,
                value_hash=item.value_hash,
                value_preview=item.value_hash[:3],
                breach_count=breach_count,
                severity=severity,
                status="new",
            )
            db.add(alert)
            await db.commit()

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    async def get_status(self, user_id: int) -> Dict[str, Any]:
        async with self._db_session_factory() as db:
            monitored = await db.scalar(
                select(sa_func.count()).where(
                    MonitoredItem.user_id == user_id,
                    MonitoredItem.is_active == True,
                )
            )
            unacked = await db.scalar(
                select(sa_func.count()).where(
                    BreachAlert.user_id == user_id,
                    BreachAlert.status == "new",
                )
            )
        return {
            "monitored_items": monitored or 0,
            "unacknowledged_alerts": unacked or 0,
            "running": self._running,
        }


# ---------------------------------------------------------------------------
# Sync convenience functions (backward compat)
# ---------------------------------------------------------------------------


def quick_check_password(password: str) -> Tuple[bool, int]:
    checker = HaveIBeenPwnedChecker()
    sha1_hash = hashlib.sha1(
        password.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    try:
        hashes = checker._fetch_hashes(prefix)
    except ConnectionError:
        return False, 0
    for line in hashes.splitlines():
        if ":" in line:
            hash_suffix, count = line.split(":", 1)
            if hash_suffix.upper() == suffix:
                return True, int(count)
    return False, 0


def quick_check_email(email: str) -> Tuple[bool, int]:
    checker = HaveIBeenPwnedChecker()
    try:
        return checker.check_email_sync(email)
    except (ConnectionError, PermissionError):
        return False, 0