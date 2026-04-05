# -*- coding: utf-8 -*-
"""
Breach Monitoring Service

Фоновый мониторинг утечек данных:
- Периодическая проверка паролей на наличие в базах HIBP
- Проверка email адресов на утечки
- Уведомления пользователя при обнаружении утечек
- История оповещений

Author: Nikita (BE1)
Version: 1.0.0
"""

import threading
import time
import hashlib
import json
import logging
from typing import List, Callable, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

from ..core.advanced_security import HaveIBeenPwnedChecker


# =============================================================================
# Enums
# =============================================================================


class AlertSeverity(Enum):
    """Уровень серьёзности оповещения."""

    LOW = "low"  # 1-100 утечек
    MEDIUM = "medium"  # 101-10000 утечек
    HIGH = "high"  # 10001-1000000 утечек
    CRITICAL = "critical"  # >1000000 утечек


class AlertStatus(Enum):
    """Статус оповещения."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class BreachAlert:
    """
    Оповещение об утечке данных.

    Attributes:
        alert_id: Уникальный идентификатор оповещения
        user_id: ID пользователя
        alert_type: Тип ('password' или 'email')
        value_hash: Хеш проверенного значения (пароль или email)
        value_preview: Первые 3 символа (для идентификации)
        breach_count: Количество утечек, где найдено значение
        severity: Уровень серьёзности
        status: Статус оповещения
        detected_at: Время обнаружения
        acknowledged_at: Время подтверждения (если есть)
        resolved_at: Время решения (если есть)
        details: Дополнительные детали от HIBP API
    """

    alert_id: str
    user_id: str
    alert_type: str  # 'password' или 'email'
    value_hash: str
    value_preview: str
    breach_count: int
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.NEW
    detected_at: float = field(default_factory=time.time)
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "alert_id": self.alert_id,
            "user_id": self.user_id,
            "alert_type": self.alert_type,
            "value_hash": self.value_hash,
            "value_preview": self.value_preview,
            "breach_count": self.breach_count,
            "severity": self.severity.value,
            "status": self.status.value,
            "detected_at": self.detected_at,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BreachAlert":
        """Десериализация из словаря."""
        return cls(
            alert_id=data["alert_id"],
            user_id=data["user_id"],
            alert_type=data["alert_type"],
            value_hash=data["value_hash"],
            value_preview=data["value_preview"],
            breach_count=data["breach_count"],
            severity=AlertSeverity(data["severity"]),
            status=AlertStatus(data["status"]),
            detected_at=data["detected_at"],
            acknowledged_at=data.get("acknowledged_at"),
            resolved_at=data.get("resolved_at"),
            details=data.get("details", {}),
        )

    @property
    def detected_datetime(self) -> datetime:
        """Время обнаружения как datetime объект."""
        return datetime.fromtimestamp(self.detected_at)

    @property
    def age_days(self) -> int:
        """Возраст оповещения в днях."""
        delta = datetime.now() - self.detected_datetime
        return delta.days


@dataclass
class MonitoredItem:
    """
    Элемент для мониторинга.

    Attributes:
        item_id: Уникальный идентификатор
        user_id: ID пользователя
        item_type: Тип ('password' или 'email')
        value_hash: Хеш значения
        created_at: Время добавления на мониторинг
        last_checked: Время последней проверки
        check_count: Количество проверок
        is_active: Активен ли мониторинг
    """

    item_id: str
    user_id: str
    item_type: str
    value_hash: str
    created_at: float = field(default_factory=time.time)
    last_checked: Optional[float] = None
    check_count: int = 0
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MonitoredItem":
        """Десериализация из словаря."""
        return cls(**data)


EmailResolver = Callable[[MonitoredItem], Optional[str]]


# =============================================================================
# Exceptions
# =============================================================================


class BreachMonitorError(Exception):
    """Базовое исключение для ошибок мониторинга утечек."""

    pass


class BreachMonitorNotAvailableError(BreachMonitorError):
    """Сервис мониторинга недоступен."""

    pass


# =============================================================================
# BreachMonitorService Class
# =============================================================================


class BreachMonitorService:
    """
    Сервис фонового мониторинга утечек данных.

    Возможности:
    - Периодическая проверка паролей и email через HIBP API
    - Уведомления при обнаружении утечек (callback)
    - История всех оповещений
    - Приоритизация по уровню серьёзности
    - Сохранение/загрузка состояния

    Пример использования:
        >>> monitor = BreachMonitorService(check_interval_hours=24)
        >>> # Добавление паролей на мониторинг
        >>> monitor.add_password("user123", "my_secure_password")
        >>> # Добавление email
        >>> monitor.add_email("user123", "user@example.com")
        >>> # Установка callback для уведомлений
        >>> monitor.set_alert_callback(on_breach_detected)
        >>> # Запуск фонового мониторинга
        >>> monitor.start()
    """

    def __init__(
        self,
        check_interval_hours: int = 24,
        api_timeout_seconds: int = 30,
        storage_path: Optional[Path] = None,
        hibp_api_key: Optional[str] = None,
        email_resolver: Optional[EmailResolver] = None,
    ):
        """
        Инициализация сервиса мониторинга.

        Args:
            check_interval_hours: Интервал проверки в часах (по умолчанию 24)
            api_timeout_seconds: Таймаут API запросов в секундах
            storage_path: Путь для хранения состояния (опционально)
            hibp_api_key: API key for HIBP email endpoint (optional, env fallback)
            email_resolver: Optional callback to resolve email by monitored item

        Example:
            >>> monitor = BreachMonitorService(
            ...     check_interval_hours=12,  # Проверка каждые 12 часов
            ...     storage_path=Path("data/breach_monitor.json")
            ... )
        """
        self._checker = HaveIBeenPwnedChecker(
            timeout=api_timeout_seconds,
            api_key=hibp_api_key,
        )
        self._logger = logging.getLogger(__name__)
        self._check_interval = check_interval_hours * 3600  # Конвертация в секунды
        self._storage_path = storage_path
        self._email_resolver = email_resolver

        # Email cache persistence (P2 fix): stores plaintext emails on disk
        # so breach checks survive process restarts without requiring email_resolver.
        self._email_cache_path: Optional[Path] = None
        if storage_path is not None:
            self._email_cache_path = storage_path.parent / "email_cache.json"

        # Хранилища данных
        self._monitored_items: Dict[str, MonitoredItem] = {}  # item_id -> MonitoredItem
        self._alerts: Dict[str, BreachAlert] = {}  # alert_id -> BreachAlert
        self._alert_callbacks: List[Callable[[BreachAlert], None]] = []
        # Runtime-only plaintext email values (never persisted to disk).
        self._runtime_emails: Dict[str, str] = {}

        # Управление потоком
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Статистика
        self._stats = {
            "total_checks": 0,
            "total_check_failures": 0,
            "total_alerts": 0,
            "last_check_time": None,
            "last_error_time": None,
            "last_error_message": None,
            "last_error_item_id": None,
            "start_time": None,
        }

        # Загрузка сохранённого состояния
        if storage_path and storage_path.exists():
            self._load_state()

        # Загрузка кэша email-адресов (P2 fix)
        self._load_email_cache()

    # ==========================================================================
    # Item Management
    # ==========================================================================

    def add_password(
        self,
        user_id: str,
        password: str,
        item_id: Optional[str] = None,
    ) -> str:
        """
        Добавить пароль на мониторинг.

        Args:
            user_id: ID пользователя
            password: Пароль для мониторинга (будет захеширован)
            item_id: Уникальный ID (генерируется если не указан)

        Returns:
            item_id добавленного элемента

        Example:
            >>> item_id = monitor.add_password("user123", "my_password")
        """
        import secrets

        # HIBP требует SHA1(password) в верхнем регистре для k-anonymity проверки.
        # Мы сохраняем только SHA1-хеш, без plaintext-пароля.
        password_hash = (
            hashlib.sha1(
                password.encode("utf-8"),
                usedforsecurity=False,  # type: ignore[arg-type]
            )
            .hexdigest()
            .upper()
        )

        # Генерация item_id
        if item_id is None:
            item_id = secrets.token_urlsafe(16)

        with self._lock:
            # Проверка дубликатов
            for existing in self._monitored_items.values():
                if (
                    existing.user_id == user_id
                    and existing.item_type == "password"
                    and existing.value_hash == password_hash
                ):
                    return existing.item_id  # Уже мониторится

            # Добавление нового элемента
            item = MonitoredItem(
                item_id=item_id,
                user_id=user_id,
                item_type="password",
                value_hash=password_hash,
            )
            self._monitored_items[item_id] = item

        return item_id

    def add_email(
        self,
        user_id: str,
        email: str,
        item_id: Optional[str] = None,
    ) -> str:
        """
        Добавить email на мониторинг.

        Args:
            user_id: ID пользователя
            email: Email для мониторинга
            item_id: Уникальный ID (генерируется если не указан)

        Returns:
            item_id добавленного элемента

        Example:
            >>> item_id = monitor.add_email("user123", "user@example.com")
        """
        import secrets

        normalized_email = self._normalize_email(email)
        # Хранение в hash-форме для дедупликации и state persistence.
        email_hash = hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()

        # Генерация item_id
        if item_id is None:
            item_id = secrets.token_urlsafe(16)

        with self._lock:
            # Проверка дубликатов
            for existing in self._monitored_items.values():
                if (
                    existing.user_id == user_id
                    and existing.item_type == "email"
                    and existing.value_hash == email_hash
                ):
                    # Refresh runtime value for active process checks.
                    self._runtime_emails[existing.item_id] = normalized_email
                    return existing.item_id  # Уже мониторится

            # Добавление нового элемента
            item = MonitoredItem(
                item_id=item_id,
                user_id=user_id,
                item_type="email",
                value_hash=email_hash,
            )
            self._monitored_items[item_id] = item
            self._runtime_emails[item_id] = normalized_email

        # Persist email cache so checks survive restarts (P2 fix)
        self._save_email_cache()

        return item_id

    def remove_item(self, item_id: str) -> bool:
        """
        Удалить элемент из мониторинга.

        Args:
            item_id: ID элемента для удаления

        Returns:
            True если элемент удалён, False если не найден
        """
        with self._lock:
            if item_id in self._monitored_items:
                del self._monitored_items[item_id]
                self._runtime_emails.pop(item_id, None)
                return True
            return False

    def remove_user_items(self, user_id: str) -> int:
        """
        Удалить все элементы пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Количество удалённых элементов
        """
        with self._lock:
            items_to_remove = [
                item_id
                for item_id, item in self._monitored_items.items()
                if item.user_id == user_id
            ]

            for item_id in items_to_remove:
                del self._monitored_items[item_id]
                self._runtime_emails.pop(item_id, None)

            return len(items_to_remove)

    def get_user_items(self, user_id: str) -> List[MonitoredItem]:
        """
        Получить все элементы пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Список MonitoredItem
        """
        with self._lock:
            return [
                item
                for item in self._monitored_items.values()
                if item.user_id == user_id and item.is_active
            ]

    # ==========================================================================
    # Alert Management
    # ==========================================================================

    def set_alert_callback(self, callback: Callable[[BreachAlert], None]) -> None:
        """
        Установить callback для оповещений.

        Args:
            callback: Функция, вызываемая при обнаружении утечки

        Example:
            >>> def on_breach(alert):
            ...     print(f"Утечка! {alert.alert_type}: {alert.value_preview}***")
            >>> monitor.set_alert_callback(on_breach)
        """
        with self._lock:
            self._alert_callbacks.append(callback)

    def remove_alert_callback(self, callback: Callable[[BreachAlert], None]) -> None:
        """
        Удалить callback.

        Args:
            callback: Callback для удаления
        """
        with self._lock:
            if callback in self._alert_callbacks:
                self._alert_callbacks.remove(callback)

    def acknowledge_alert(self, alert_id: str) -> bool:
        """
        Подтвердить оповещение.

        Args:
            alert_id: ID оповещения

        Returns:
            True если оповещение подтверждено
        """
        with self._lock:
            if alert_id in self._alerts:
                self._alerts[alert_id].acknowledged_at = time.time()
                self._alerts[alert_id].status = AlertStatus.ACKNOWLEDGED
                return True
            return False

    def resolve_alert(self, alert_id: str) -> bool:
        """
        Закрыть оповещение (проблема решена).

        Args:
            alert_id: ID оповещения

        Returns:
            True если оповещение закрыто
        """
        with self._lock:
            if alert_id in self._alerts:
                self._alerts[alert_id].resolved_at = time.time()
                self._alerts[alert_id].status = AlertStatus.RESOLVED
                return True
            return False

    def get_alerts(
        self,
        user_id: Optional[str] = None,
        status: Optional[AlertStatus] = None,
        severity: Optional[AlertSeverity] = None,
        limit: int = 100,
    ) -> List[BreachAlert]:
        """
        Получить оповещения с фильтрацией.

        Args:
            user_id: Фильтр по пользователю
            status: Фильтр по статусу
            severity: Фильтр по серьёзности
            limit: Максимальное количество результатов

        Returns:
            Список BreachAlert
        """
        with self._lock:
            alerts = list(self._alerts.values())

            # Применение фильтров
            if user_id:
                alerts = [a for a in alerts if a.user_id == user_id]
            if status:
                alerts = [a for a in alerts if a.status == status]
            if severity:
                alerts = [a for a in alerts if a.severity == severity]

            # Сортировка по времени (новые сначала)
            alerts.sort(key=lambda x: x.detected_at, reverse=True)

            return alerts[:limit]

    def get_unacknowledged_alerts(
        self, user_id: Optional[str] = None
    ) -> List[BreachAlert]:
        """
        Получить неподтверждённые оповещения.

        Args:
            user_id: Фильтр по пользователю

        Returns:
            Список неподтверждённых оповещений
        """
        return self.get_alerts(
            user_id=user_id,
            status=AlertStatus.NEW,
        )

    # ==========================================================================
    # Monitoring Control
    # ==========================================================================

    def start(self) -> None:
        """
        Запуск фонового мониторинга.

        Example:
            >>> monitor.start()
            >>> # Мониторинг работает в фоновом потоке
        """
        self._ensure_email_resolution_ready()
        with self._lock:
            if self._running:
                return

            self._running = True
            self._stats["start_time"] = time.time()
            self._thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True,
                name="BreachMonitor",
            )
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """
        Остановка мониторинга.

        Args:
            timeout: Максимальное время ожидания остановки потока
        """
        with self._lock:
            if not self._running:
                return

            self._running = False

        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

    def check_now(self, user_id: Optional[str] = None) -> int:
        """
        Немедленная проверка всех элементов.

        Args:
            user_id: Проверить только элементы пользователя (None = все)

        Returns:
            Количество успешно проверенных элементов

        Raises:
            BreachMonitorError: Если часть проверок завершилась ошибкой
        """
        self._ensure_email_resolution_ready(user_id=user_id)

        with self._lock:
            items_to_check = list(self._monitored_items.values())

            if user_id:
                items_to_check = [i for i in items_to_check if i.user_id == user_id]

            # Фильтрация неактивных
            items_to_check = [i for i in items_to_check if i.is_active]

        checked_count = 0
        errors: List[Tuple[str, Exception]] = []
        for item in items_to_check:
            try:
                self._check_item(item)
                checked_count += 1
            except Exception as exc:
                errors.append((item.item_id, exc))
                self._record_check_error(item.item_id, exc)

        if errors:
            failed_items = ", ".join(item_id for item_id, _ in errors[:5])
            if len(errors) > 5:
                failed_items = f"{failed_items}, ..."
            first_error = errors[0][1]
            raise BreachMonitorError(
                f"check_now failed for {len(errors)} item(s): {failed_items}"
            ) from first_error

        return checked_count

    def check_now_safe(
        self, user_id: Optional[str] = None
    ) -> Tuple[int, Dict[str, str]]:
        """
        Check all items without raising on failure.

        Unlike check_now(), this method never raises. It returns
        both the success count and a dict of failed item IDs
        mapped to their error messages.

        Args:
            user_id: Check only this user's items (None = all)

        Returns:
            Tuple of (success_count, error_dict) where error_dict
            maps item_id to error message string.

        Example:
            >>> ok, errs = monitor.check_now_safe()
            >>> print(f"Checked {ok}, failed {len(errs)}")
        """
        self._ensure_email_resolution_ready(user_id=user_id)

        with self._lock:
            items_to_check = list(self._monitored_items.values())

            if user_id:
                items_to_check = [i for i in items_to_check if i.user_id == user_id]

            items_to_check = [i for i in items_to_check if i.is_active]

        checked_count = 0
        errors: Dict[str, str] = {}
        for item in items_to_check:
            try:
                self._check_item(item)
                checked_count += 1
            except Exception as exc:
                errors[item.item_id] = f"{exc.__class__.__name__}: {exc}"
                self._record_check_error(item.item_id, exc)

        return checked_count, errors

    def _monitor_loop(self) -> None:
        """Основной цикл мониторинга."""
        while self._running:
            try:
                # Проверка всех активных элементов
                with self._lock:
                    items_to_check = [
                        item
                        for item in self._monitored_items.values()
                        if item.is_active
                    ]

                for item in items_to_check:
                    if not self._running:
                        break
                    try:
                        self._check_item(item)
                    except Exception as exc:
                        self._record_check_error(item.item_id, exc)

                # Обновление статистики
                with self._lock:
                    self._stats["last_check_time"] = time.time()

                # Ожидание следующего цикла
                if self._running:
                    time.sleep(self._check_interval)

            except Exception as e:
                self._record_check_error(None, e)
                if self._running:
                    time.sleep(60)  # Пауза перед повторной попыткой

    def _check_item(self, item: MonitoredItem) -> None:
        """
        Проверка одного элемента.

        Args:
            item: Элемент для проверки
        """
        is_pwned = False
        breach_count = 0

        if item.item_type == "password":
            # Проверка пароля по HIBP k-anonymity:
            # отправляется только префикс SHA1-хеша (5 символов).
            sha1_hash = item.value_hash.upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            hashes = self._checker._fetch_hashes(prefix)
            for line in hashes.splitlines():
                if ":" not in line:
                    continue
                hash_suffix, count = line.split(":", 1)
                if hash_suffix.upper() == suffix:
                    is_pwned = True
                    breach_count = int(count)
                    break

        elif item.item_type == "email":
            resolved_email = self._resolve_email_for_item(item)
            is_pwned, breach_count = self._checker.check_email(resolved_email)
        else:
            raise ValueError(f"Unsupported monitored item type: {item.item_type}")

        # Обновление статистики элемента
        with self._lock:
            item.last_checked = time.time()
            item.check_count += 1
            self._stats["total_checks"] += 1

        # Создание оповещения при обнаружении утечки
        if is_pwned and breach_count > 0:
            self._create_alert(item, breach_count)

    def _create_alert(
        self,
        item: MonitoredItem,
        breach_count: int,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Создание оповещения об утечке.

        Args:
            item: Элемент, для которого создана утечка
            breach_count: Количество утечек
            details: Дополнительные детали
        """
        import secrets

        # Определение серьёзности
        severity = self._calculate_severity(breach_count)

        # Создание оповещения
        alert = BreachAlert(
            alert_id=secrets.token_urlsafe(16),
            user_id=item.user_id,
            alert_type=item.item_type,
            value_hash=item.value_hash,
            value_preview=item.value_hash[:3],
            breach_count=breach_count,
            severity=severity,
            details=details or {},
        )

        # Сохранение оповещения
        with self._lock:
            self._alerts[alert.alert_id] = alert
            self._stats["total_alerts"] += 1

        # Уведомление через callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self._logger.exception(
                    "[BreachMonitor] Ошибка callback для alert_id=%s: %s",
                    alert.alert_id,
                    e,
                )

    def _calculate_severity(self, breach_count: int) -> AlertSeverity:
        """
        Расчёт уровня серьёзности по количеству утечек.

        Args:
            breach_count: Количество утечек

        Returns:
            AlertSeverity
        """
        if breach_count > 1_000_000:
            return AlertSeverity.CRITICAL
        elif breach_count > 10_000:
            return AlertSeverity.HIGH
        elif breach_count > 100:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

    def _record_check_error(self, item_id: Optional[str], error: Exception) -> None:
        """Record structured monitoring error for diagnostics and observability."""
        message = f"{error.__class__.__name__}: {error}"
        with self._lock:
            self._stats["total_check_failures"] += 1
            self._stats["last_error_time"] = time.time()
            self._stats["last_error_message"] = message
            self._stats["last_error_item_id"] = item_id
        self._logger.exception(
            "[BreachMonitor] Ошибка проверки item_id=%s: %s",
            item_id,
            message,
        )

    def _ensure_email_resolution_ready(self, user_id: Optional[str] = None) -> None:
        """
        Ensure persisted email checks are resolvable in current runtime.

        After process restart runtime email cache is empty by design. In that case
        caller must provide `email_resolver` to resolve plaintext email values.
        """
        with self._lock:
            if self._email_resolver is not None:
                return

            unresolved_email_items = [
                item.item_id
                for item in self._monitored_items.values()
                if item.is_active
                and item.item_type == "email"
                and (user_id is None or item.user_id == user_id)
                and item.item_id not in self._runtime_emails
            ]

        if unresolved_email_items:
            preview = ", ".join(unresolved_email_items[:5])
            if len(unresolved_email_items) > 5:
                preview = f"{preview}, ..."
            raise BreachMonitorNotAvailableError(
                "Email checks require runtime email values. "
                "Re-add monitored emails in current process or provide email_resolver. "
                f"Unresolvable item_ids: {preview}"
            )

    def _normalize_email(self, email: str) -> str:
        """Normalize email for stable hashing/checking."""
        normalized = email.strip().lower()
        if not normalized:
            raise ValueError("Email must not be empty")
        return normalized

    def _resolve_email_for_item(self, item: MonitoredItem) -> str:
        """
        Resolve email for check without persisting plaintext to storage.

        Resolution order:
        1. Runtime-only cache (set on add_email)
        2. Optional external resolver callback
        """
        runtime_email = self._runtime_emails.get(item.item_id)
        if runtime_email:
            return runtime_email

        if self._email_resolver is not None:
            resolved_email = self._email_resolver(item)
            if resolved_email:
                normalized = self._normalize_email(resolved_email)
                resolved_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
                if resolved_hash != item.value_hash:
                    raise BreachMonitorError(
                        f"Email resolver returned value mismatched with item hash: {item.item_id}"
                    )
                with self._lock:
                    self._runtime_emails[item.item_id] = normalized
                return normalized

        raise BreachMonitorNotAvailableError(
            "Email value unavailable for check. Re-add email in current runtime "
            "or provide email_resolver callback for persisted items."
        )

    def _get_email_from_hash(self, email_hash: str) -> str:
        """
        Legacy compatibility helper.

        One-way hash is intentionally non-reversible. Kept for compatibility.

        Args:
            email_hash: SHA-256 хеш email

        Returns:
            Never returns
        """
        raise NotImplementedError(
            "Email lookup from hash is intentionally unsupported."
        )

    # ==========================================================================
    # Email Cache Persistence (P2 fix)
    # ==========================================================================

    def _save_email_cache(self) -> None:
        """
        Persist runtime email values to disk so breach checks survive restarts.

        Stores a mapping of item_id -> plaintext email in a JSON file
        alongside the main state file. This is NOT encrypted — the file
        should be stored in a directory with restricted permissions.

        Called automatically on add_email and before process shutdown.
        """
        if self._email_cache_path is None:
            return

        with self._lock:
            if not self._runtime_emails:
                return
            cache = dict(self._runtime_emails)

        try:
            self._email_cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._email_cache_path, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._logger.warning("[BreachMonitor] Failed to save email cache: %s", e)

    def _load_email_cache(self) -> None:
        """
        Load persisted email values from disk after process restart.

        Restores the _runtime_emails dict from the JSON cache file
        so that email breach checks can proceed without requiring
        the user to re-add emails or provide an email_resolver.
        """
        if self._email_cache_path is None or not self._email_cache_path.exists():
            return

        try:
            with open(self._email_cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)

            with self._lock:
                self._runtime_emails.update(cache)

            self._logger.info(
                "[BreachMonitor] Loaded %d email(s) from cache",
                len(cache),
            )
        except Exception as e:
            self._logger.warning("[BreachMonitor] Failed to load email cache: %s", e)

    def _save_email_cache(self) -> None:
        """
        Persist runtime email values to disk so breach checks survive restarts.

        Stores a mapping of item_id -> plaintext email in a JSON file
        alongside the main state file. This is NOT encrypted — the file
        should be stored in a directory with restricted permissions.

        Called automatically on add_email and before process shutdown.
        """
        if self._email_cache_path is None:
            return

        with self._lock:
            if not self._runtime_emails:
                return
            cache = dict(self._runtime_emails)

        try:
            self._email_cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._email_cache_path, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._logger.warning("[BreachMonitor] Failed to save email cache: %s", e)

    def _load_email_cache(self) -> None:
        """
        Load persisted email values from disk after process restart.

        Restores the _runtime_emails dict from the JSON cache file
        so that email breach checks can proceed without requiring
        the user to re-add emails or provide an email_resolver.
        """
        if self._email_cache_path is None or not self._email_cache_path.exists():
            return

        try:
            with open(self._email_cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)

            with self._lock:
                self._runtime_emails.update(cache)

            self._logger.info(
                "[BreachMonitor] Loaded %d email(s) from cache",
                len(cache),
            )
        except Exception as e:
            self._logger.warning("[BreachMonitor] Failed to load email cache: %s", e)

    # ==========================================================================
    # Persistence
    # ==========================================================================

    def save_state(self) -> None:
        """
        Сохранение текущего состояния в файл.

        Example:
            >>> monitor.save_state()
            # Сохраняет в storage_path из конструктора
        """
        if not self._storage_path:
            return

        with self._lock:
            state = {
                "monitored_items": {
                    k: v.to_dict() for k, v in self._monitored_items.items()
                },
                "alerts": {k: v.to_dict() for k, v in self._alerts.items()},
                "stats": self._stats,
            }

            # Создание директории если не существует
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)

            # Сохранение в JSON
            with open(self._storage_path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, ensure_ascii=False)

    def _load_state(self) -> None:
        """Загрузка состояния из файла."""
        if not self._storage_path or not self._storage_path.exists():
            return

        try:
            with open(self._storage_path, "r", encoding="utf-8") as f:
                state = json.load(f)

            with self._lock:
                # Загрузка элементов
                self._monitored_items = {
                    k: MonitoredItem.from_dict(v)
                    for k, v in state.get("monitored_items", {}).items()
                }

                # Загрузка оповещений
                self._alerts = {
                    k: BreachAlert.from_dict(v)
                    for k, v in state.get("alerts", {}).items()
                }

                # Загрузка статистики
                self._stats.update(state.get("stats", {}))

        except Exception as e:
            self._logger.exception("[BreachMonitor] Ошибка загрузки состояния: %s", e)

    # ==========================================================================
    # Statistics
    # ==========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """
        Получить статистику сервиса.

        Returns:
            Словарь со статистикой
        """
        with self._lock:
            return {
                **self._stats,
                "running": self._running,
                "monitored_items_count": len(self._monitored_items),
                "total_alerts_count": len(self._alerts),
                "unacknowledged_alerts": len(
                    [a for a in self._alerts.values() if a.status == AlertStatus.NEW]
                ),
                "check_interval_hours": self._check_interval / 3600,
            }

    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """
        Получить статистику для конкретного пользователя.

        Args:
            user_id: ID пользователя

        Returns:
            Словарь со статистикой
        """
        with self._lock:
            user_items = [
                i for i in self._monitored_items.values() if i.user_id == user_id
            ]

            user_alerts = [a for a in self._alerts.values() if a.user_id == user_id]

            return {
                "monitored_items": len(user_items),
                "total_alerts": len(user_alerts),
                "unacknowledged_alerts": len(
                    [a for a in user_alerts if a.status == AlertStatus.NEW]
                ),
                "critical_alerts": len(
                    [a for a in user_alerts if a.severity == AlertSeverity.CRITICAL]
                ),
                "last_check": max(
                    (i.last_checked for i in user_items),
                    default=None,
                ),
            }


# =============================================================================
# Convenience Functions
# =============================================================================


def quick_check_password(password: str) -> Tuple[bool, int]:
    """
    Быстрая проверка пароля на утечки.

    Args:
        password: Пароль для проверки

    Returns:
        Tuple[is_pwned, breach_count]

    Example:
        >>> is_pwned, count = quick_check_password("password123")
        >>> if is_pwned:
        ...     print(f"Пароль найден в {count} утечках!")
    """
    checker = HaveIBeenPwnedChecker()
    return checker.check_password(password)


def quick_check_email(email: str) -> Tuple[bool, int]:
    """
    Быстрая проверка email на утечки.

    Args:
        email: Email для проверки

    Returns:
        Tuple[is_pwned, breach_count]

    Example:
        >>> is_pwned, count = quick_check_email("user@example.com")
    """
    checker = HaveIBeenPwnedChecker()
    return checker.check_email(email)


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Enums
    "AlertSeverity",
    "AlertStatus",
    # Data classes
    "BreachAlert",
    "MonitoredItem",
    # Exceptions
    "BreachMonitorError",
    "BreachMonitorNotAvailableError",
    # Main class
    "BreachMonitorService",
    # Convenience functions
    "quick_check_password",
    "quick_check_email",
]
