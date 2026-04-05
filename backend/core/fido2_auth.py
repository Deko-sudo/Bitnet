# -*- coding: utf-8 -*-
"""
FIDO2/WebAuthn Authentication

Поддержка аппаратных ключей безопасности:
- YubiKey 5 Series
- Google Titan Key
- Solo Key
- Any FIDO2-compatible device

Author: Nikita (BE1)
Version: 1.0.0
"""

import time
import secrets
import base64
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

try:
    from fido2.client import Fido2Client
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
    )
    from fido2.utils import websafe_encode, websafe_decode
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False
    Fido2Client = None
    Fido2Server = None
    PublicKeyCredentialRpEntity = None
    PublicKeyCredentialUserEntity = None
    PublicKeyCredentialCreationOptions = None
    PublicKeyCredentialRequestOptions = None
    websafe_encode = None
    websafe_decode = None


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class FIDO2Key:
    """
    FIDO2 ключ с метаданными.
    
    Attributes:
        key_id: Уникальный идентификатор ключа
        user_id: ID пользователя, которому принадлежит ключ
        credential_id: Credential ID от FIDO2 устройства
        public_key: Публичный ключ (для верификации)
        created_at: Время регистрации ключа
        last_used: Время последнего использования
        device_name: Название устройства (например, "YubiKey 5")
        transports: Поддерживаемые транспорты (usb, nfc, ble)
    """
    key_id: str
    user_id: str
    credential_id: bytes
    public_key: bytes
    created_at: float
    last_used: Optional[float] = None
    device_name: str = "Unknown"
    transports: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь (для хранения в БД)."""
        return {
            'key_id': self.key_id,
            'user_id': self.user_id,
            'credential_id': base64.b64encode(self.credential_id).decode('ascii'),
            'public_key': base64.b64encode(self.public_key).decode('ascii'),
            'created_at': self.created_at,
            'last_used': self.last_used,
            'device_name': self.device_name,
            'transports': self.transports,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FIDO2Key':
        """Десериализация из словаря."""
        return cls(
            key_id=data['key_id'],
            user_id=data['user_id'],
            credential_id=base64.b64decode(data['credential_id']),
            public_key=base64.b64decode(data['public_key']),
            created_at=data['created_at'],
            last_used=data.get('last_used'),
            device_name=data.get('device_name', 'Unknown'),
            transports=data.get('transports', []),
        )


# =============================================================================
# Exceptions
# =============================================================================

class FIDO2Error(Exception):
    """Базовое исключение для ошибок FIDO2."""
    pass


class FIDO2NotAvailableError(FIDO2Error):
    """FIDO2 библиотека не доступна."""
    pass


class FIDO2RegistrationError(FIDO2Error):
    """Ошибка регистрации FIDO2 ключа."""
    pass


class FIDO2AuthenticationError(FIDO2Error):
    """Ошибка аутентификации FIDO2."""
    pass


class FIDO2NoKeysError(FIDO2Error):
    """У пользователя нет зарегистрированных FIDO2 ключей."""
    pass


# =============================================================================
# FIDO2Authenticator Class
# =============================================================================

class FIDO2Authenticator:
    """
    FIDO2 аутентификация с аппаратными ключами.
    
    Поддерживаемые устройства:
    - YubiKey 5 Series (5 NFC, 5C, 5Ci)
    - Google Titan Security Key
    - Solo Key
    - Any FIDO2-certified device
    
    Пример использования:
        >>> fido = FIDO2Authenticator(rp_id="example.com", rp_name="Password Manager")
        >>> # Регистрация нового ключа
        >>> options, state = fido.start_registration("user123", "user@example.com")
        >>> # Пользователь вставляет ключ и нажимает кнопку
        >>> credential = fido.complete_registration(state, client_response)
        >>> # Аутентификация
        >>> options, state = fido.start_authentication("user123")
        >>> credential = fido.complete_authentication(state, client_response)
    
    Security Notes:
    - Приватные ключи никогда не покидают устройство
    - Каждая аутентификация использует уникальный signature counter
    - Поддержка user presence (касание) и user verification (PIN/biometric)
    """
    
    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        rp_icon: Optional[str] = None,
        timeout: int = 60000,
    ):
        """
        Инициализация FIDO2.
        
        Args:
            rp_id: Relying Party ID (домен, например "example.com")
            rp_name: Relying Party Name (отображаемое имя, например "Password Manager")
            rp_icon: URL иконки (опционально)
            timeout: Таймаут операции в миллисекундах (по умолчанию 60 секунд)
        
        Raises:
            FIDO2NotAvailableError: Если библиотека python-fido2 не установлена
        
        Example:
            >>> fido = FIDO2Authenticator(
            ...     rp_id="password-manager.local",
            ...     rp_name="My Password Manager"
            ... )
        """
        if not FIDO2_AVAILABLE:
            raise FIDO2NotAvailableError(
                "Библиотека python-fido2 не установлена. "
                "Установите: pip install python-fido2>=1.1.0"
            )
        
        self._rp = PublicKeyCredentialRpEntity(
            id=rp_id,
            name=rp_name,
            icon=rp_icon,
        )
        self._rp_id = rp_id
        self._timeout = timeout
        
        # Инициализация FIDO2 сервера
        self._server = Fido2Server(rp_id, self._rp)
        
        # Хранилище ключей (в production использовать БД)
        # Структура: {user_id: {credential_id: FIDO2Key}}
        self._credentials: Dict[str, Dict[bytes, FIDO2Key]] = {}
        
        # Временное состояние для регистрации/аутентификации
        self._registration_state: Dict[str, Any] = {}
        self._authentication_state: Dict[str, Any] = {}
    
    # ==========================================================================
    # Registration Methods
    # ==========================================================================
    
    def start_registration(
        self,
        user_id: str,
        username: str,
        display_name: Optional[str] = None,
        icon: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str]:
        """
        Начало регистрации нового FIDO2 ключа.
        
        Args:
            user_id: Внутренний ID пользователя (уникальный)
            username: Имя пользователя (email или логин)
            display_name: Отображаемое имя (опционально)
            icon: URL аватара (опционально)
        
        Returns:
            Tuple[options_for_client, state_id]
            options_for_client: Данные для отправки клиенту (JSON)
            state_id: Идентификатор состояния для complete_registration
        
        Raises:
            FIDO2RegistrationError: Если не удалось начать регистрацию
        
        Example:
            >>> options, state_id = fido.start_registration(
            ...     user_id="user123",
            ...     username="user@example.com"
            ... )
            >>> # Отправить options клиенту для создания credential
        """
        try:
            # Создание пользователя
            user = PublicKeyCredentialUserEntity(
                id=user_id.encode('utf-8'),
                name=username,
                display_name=display_name or username,
                icon=icon,
            )
            
            # Начало регистрации
            register_options, state = self._server.register_begin(
                user_id=user_id.encode('utf-8'),
                user=user,
                authenticator_attachment="cross-platform",  # USB/NFC ключи
            )
            
            # Сохранение состояния
            state_id = secrets.token_urlsafe(32)
            self._registration_state[state_id] = {
                'state': state,
                'user_id': user_id,
                'created_at': time.time(),
            }
            
            # Очистка старых состояний (>5 минут)
            self._cleanup_old_states(self._registration_state, 300)
            
            return dict(register_options), state_id
        
        except Exception as e:
            raise FIDO2RegistrationError(f"Не удалось начать регистрацию: {e}")
    
    def complete_registration(
        self,
        state_id: str,
        client_response: Dict[str, Any],
        origin: str,
    ) -> FIDO2Key:
        """
        Завершение регистрации FIDO2 ключа.
        
        Args:
            state_id: Идентификатор состояния из start_registration
            client_response: Ответ от клиента с credential
            origin: Origin клиента (например, "https://example.com")
        
        Returns:
            FIDO2Key: Зарегистрированный ключ
        
        Raises:
            FIDO2RegistrationError: Если регистрация не удалась
            ValueError: Если state_id не найден или истёк
        
        Example:
            >>> key = fido.complete_registration(
            ...     state_id="abc123...",
            ...     client_response=response,
            ...     origin="https://example.com"
            ... )
        """
        try:
            # Проверка состояния
            if state_id not in self._registration_state:
                raise ValueError("state_id не найден. Возможно, истёк таймаут.")
            
            state_data = self._registration_state[state_id]
            state = state_data['state']
            user_id = state_data['user_id']
            
            # Извлечение ответа
            if 'response' in client_response:
                response = client_response['response']
            else:
                response = client_response
            
            # Завершение регистрации на сервере
            auth_data, client_data = self._server.register_complete(
                state,
                response,
                origin,
            )
            
            # Создание FIDO2Key
            credential_id = auth_data.credential_data['credential_id']
            public_key = auth_data.credential_data['credential_public_key']
            
            # Определение устройства по transports
            transports = []
            if 'transports' in response:
                transports = response['transports']
            
            key = FIDO2Key(
                key_id=secrets.token_urlsafe(16),
                user_id=user_id,
                credential_id=credential_id,
                public_key=public_key,
                created_at=time.time(),
                device_name=self._detect_device_name(transports),
                transports=transports,
            )
            
            # Сохранение ключа
            if user_id not in self._credentials:
                self._credentials[user_id] = {}
            self._credentials[user_id][credential_id] = key
            
            # Очистка состояния
            del self._registration_state[state_id]
            
            return key
        
        except Exception as e:
            raise FIDO2RegistrationError(f"Регистрация не удалась: {e}")
    
    # ==========================================================================
    # Authentication Methods
    # ==========================================================================
    
    def start_authentication(
        self,
        user_id: str,
        user_verification: str = "discouraged",
    ) -> Tuple[Dict[str, Any], str]:
        """
        Начало аутентификации с FIDO2 ключом.
        
        Args:
            user_id: ID пользователя
            user_verification: Уровень верификации
                - "required": Требуется PIN/biometric
                - "preferred": Предпочтительно, но не обязательно
                - "discouraged": Не требуется (только touch)
        
        Returns:
            Tuple[options_for_client, state_id]
            options_for_client: Данные для отправки клиенту (JSON)
            state_id: Идентификатор состояния для complete_authentication
        
        Raises:
            FIDO2NoKeysError: Если у пользователя нет зарегистрированных ключей
            FIDO2AuthenticationError: Если не удалось начать аутентификацию
        
        Example:
            >>> options, state_id = fido.start_authentication("user123")
            >>> # Отправить options клиенту для аутентификации
        """
        try:
            # Проверка наличия ключей
            if user_id not in self._credentials or not self._credentials[user_id]:
                raise FIDO2NoKeysError(
                    f"У пользователя {user_id} нет зарегистрированных FIDO2 ключей"
                )
            
            # Получение credential IDs
            credential_ids = list(self._credentials[user_id].keys())
            
            # Начало аутентификации
            auth_options, state = self._server.authenticate_begin(
                credential_ids,
                user_verification=user_verification,
            )
            
            # Сохранение состояния
            state_id = secrets.token_urlsafe(32)
            self._authentication_state[state_id] = {
                'state': state,
                'user_id': user_id,
                'created_at': time.time(),
            }
            
            # Очистка старых состояний
            self._cleanup_old_states(self._authentication_state, 300)
            
            return dict(auth_options), state_id
        
        except FIDO2NoKeysError:
            raise
        except Exception as e:
            raise FIDO2AuthenticationError(f"Не удалось начать аутентификацию: {e}")
    
    def complete_authentication(
        self,
        state_id: str,
        client_response: Dict[str, Any],
        origin: str,
    ) -> Tuple[bool, str, Optional[FIDO2Key]]:
        """
        Завершение аутентификации.
        
        Args:
            state_id: Идентификатор состояния из start_authentication
            client_response: Ответ от клиента с assertion
            origin: Origin клиента (например, "https://example.com")
        
        Returns:
            Tuple[success, error_message, key]
            success: True если аутентификация успешна
            error_message: Сообщение об ошибке (пустое если успешно)
            key: FIDO2Key если успешно, None иначе
        
        Raises:
            ValueError: Если state_id не найден или истёк
        
        Example:
            >>> success, error, key = fido.complete_authentication(
            ...     state_id="abc123...",
            ...     client_response=response,
            ...     origin="https://example.com"
            ... )
            >>> if success:
            ...     print(f"Аутентификация успешна! Ключ: {key.key_id}")
        """
        try:
            # Проверка состояния
            if state_id not in self._authentication_state:
                return False, "state_id не найден. Возможно, истёк таймаут.", None
            
            state_data = self._authentication_state[state_id]
            state = state_data['state']
            user_id = state_data['user_id']
            
            # Извлечение ответа
            if 'response' in client_response:
                response = client_response['response']
            else:
                response = client_response
            
            # Завершение аутентификации
            self._server.authenticate_complete(
                state,
                response,
                origin,
            )
            
            # Обновление last_used
            credential_id = response.get('id', '').encode('utf-8')
            credential_id = websafe_decode(credential_id) if websafe_decode else credential_id
            
            key = None
            if user_id in self._credentials and credential_id in self._credentials[user_id]:
                key = self._credentials[user_id][credential_id]
                key.last_used = time.time()
            
            # Очистка состояния
            del self._authentication_state[state_id]
            
            return True, "", key
        
        except Exception as e:
            return False, f"Аутентификация не удалась: {e}", None
    
    # ==========================================================================
    # Key Management Methods
    # ==========================================================================
    
    def get_user_keys(self, user_id: str) -> List[FIDO2Key]:
        """
        Получить все ключи пользователя.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            Список FIDO2Key
        
        Example:
            >>> keys = fido.get_user_keys("user123")
            >>> for key in keys:
            ...     print(f"Key: {key.key_id}, Device: {key.device_name}")
        """
        if user_id not in self._credentials:
            return []
        return list(self._credentials[user_id].values())
    
    def get_key(self, user_id: str, key_id: str) -> Optional[FIDO2Key]:
        """
        Получить конкретный ключ по ID.
        
        Args:
            user_id: ID пользователя
            key_id: ID ключа
        
        Returns:
            FIDO2Key или None если не найден
        """
        if user_id not in self._credentials:
            return None
        
        for key in self._credentials[user_id].values():
            if key.key_id == key_id:
                return key
        return None
    
    def delete_key(self, user_id: str, key_id: str) -> bool:
        """
        Удалить ключ пользователя.
        
        Args:
            user_id: ID пользователя
            key_id: ID ключа для удаления
        
        Returns:
            True если ключ удалён, False если не найден
        
        Example:
            >>> if fido.delete_key("user123", "key_abc"):
            ...     print("Ключ удалён")
        """
        if user_id not in self._credentials:
            return False
        
        credentials = self._credentials[user_id]
        
        # Поиск ключа по key_id
        for cred_id, key in list(credentials.items()):
            if key.key_id == key_id:
                del credentials[cred_id]
                return True
        
        return False
    
    def delete_all_user_keys(self, user_id: str) -> int:
        """
        Удалить все ключи пользователя.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            Количество удалённых ключей
        """
        if user_id not in self._credentials:
            return 0
        
        count = len(self._credentials[user_id])
        del self._credentials[user_id]
        return count
    
    # ==========================================================================
    # Challenge-Response Methods
    # ==========================================================================
    
    def generate_challenge(self, user_id: str) -> Tuple[str, str]:
        """
        Генерация challenge для challenge-response аутентификации.
        
        Challenge-response используется для:
        - Разблокировки хранилища паролей
        - Подписи транзакций
        - Верификации операций
        
        Args:
            user_id: ID пользователя
        
        Returns:
            Tuple[challenge, state_id]
            challenge: Base64-encoded challenge для отправки клиенту
            state_id: Идентификатор для verify_challenge
        
        Example:
            >>> challenge, state_id = fido.generate_challenge("user123")
            >>> # Отправить challenge клиенту для подписи
        """
        # Генерация криптографически случайного challenge
        challenge = secrets.token_bytes(32)
        challenge_b64 = base64.b64encode(challenge).decode('ascii')
        
        # Сохранение состояния
        state_id = secrets.token_urlsafe(32)
        self._authentication_state[state_id] = {
            'challenge': challenge,
            'user_id': user_id,
            'created_at': time.time(),
            'type': 'challenge_response',
        }
        
        return challenge_b64, state_id
    
    def verify_challenge(
        self,
        state_id: str,
        signature: str,
        credential_id: str,
    ) -> Tuple[bool, str]:
        """
        Верификация challenge-response.
        
        Args:
            state_id: Идентификатор из generate_challenge
            signature: Base64-encoded подпись от клиента
            credential_id: ID ключа, которым подписано
        
        Returns:
            Tuple[success, error_message]
        
        Note:
            Эта метода требует дополнительной реализации для верификации
            подписи с использованием публичного ключа. В данной версии
            используется упрощённая верификация через authenticate_complete.
        """
        # Проверка состояния
        if state_id not in self._authentication_state:
            return False, "state_id не найден или истёк"
        
        state_data = self._authentication_state[state_id]
        
        # Проверка типа
        if state_data.get('type') != 'challenge_response':
            return False, "Неверный тип состояния"
        
        # Проверка таймаута (5 минут)
        if time.time() - state_data['created_at'] > 300:
            del self._authentication_state[state_id]
            return False, "Таймаут challenge"
        
        # В production здесь должна быть полная верификация подписи
        # с использованием публичного ключа из FIDO2Key
        
        # Очистка состояния
        del self._authentication_state[state_id]
        
        # Для полной реализации требуется:
        # 1. Получить публичный ключ из FIDO2Key
        # 2. Верифицировать подпись через cryptography.hazmat
        # 3. Проверить signature counter для защиты от replay attacks
        #
        # Без этих шагов подтверждать challenge небезопасно, поэтому
        # возвращаем отказ (fail-safe) вместо ложного успеха.
        return False, "Challenge verification is not securely implemented"
    
    # ==========================================================================
    # Utility Methods
    # ==========================================================================
    
    def _detect_device_name(self, transports: List[str]) -> str:
        """
        Определение названия устройства по transports.
        
        Args:
            transports: Список транспортов от устройства
        
        Returns:
            Название устройства
        """
        if not transports:
            return "Unknown FIDO2 Device"
        
        if 'nfc' in transports:
            if 'usb' in transports:
                return "YubiKey 5 NFC"
            return "NFC FIDO2 Key"
        elif 'usb' in transports:
            return "USB FIDO2 Key"
        elif 'ble' in transports:
            return "Bluetooth FIDO2 Key"
        elif 'internal' in transports:
            return "Platform Authenticator"
        
        return "FIDO2 Device"
    
    def _cleanup_old_states(self, states: Dict[str, Any], max_age: int) -> None:
        """
        Очистка старых состояний.
        
        Args:
            states: Словарь состояний для очистки
            max_age: Максимальный возраст в секундах
        """
        now = time.time()
        expired = [
            state_id for state_id, data in states.items()
            if now - data['created_at'] > max_age
        ]
        
        for state_id in expired:
            del states[state_id]
    
    def has_user_keys(self, user_id: str) -> bool:
        """
        Проверка наличия ключей у пользователя.
        
        Args:
            user_id: ID пользователя
        
        Returns:
            True если есть ключи
        """
        return user_id in self._credentials and bool(self._credentials[user_id])
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Получить статистику использования FIDO2.
        
        Returns:
            Словарь со статистикой
        """
        total_keys = sum(len(keys) for keys in self._credentials.values())
        total_users = len(self._credentials)
        
        return {
            'total_users': total_users,
            'total_keys': total_keys,
            'pending_registrations': len(self._registration_state),
            'pending_authentications': len(self._authentication_state),
            'fido2_available': FIDO2_AVAILABLE,
        }


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Data classes
    'FIDO2Key',
    
    # Exceptions
    'FIDO2Error',
    'FIDO2NotAvailableError',
    'FIDO2RegistrationError',
    'FIDO2AuthenticationError',
    'FIDO2NoKeysError',
    
    # Main class
    'FIDO2Authenticator',
    
    # Feature flag
    'FIDO2_AVAILABLE',
]
