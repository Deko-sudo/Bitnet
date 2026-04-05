# -*- coding: utf-8 -*-
"""
Auth Manager - Authentication and Session Management

Provides:
- Master key storage in memory
- Auto-lock timer
- Session management
- Secure lock/unlock operations
- Ephemeral key lifecycle via context manager

Author: Nikita (BE1)
Version: 2.0
"""

import threading
import time
from contextlib import contextmanager
from typing import Optional, Callable, Any, Literal, Iterator
from dataclasses import dataclass, field

from .crypto_core import CryptoCore, zero_memory
from .secure_delete import SecureString
from .config import CryptoConfig


# =============================================================================
# Exceptions
# =============================================================================


class AuthError(Exception):
    """Base exception for authentication errors."""

    pass


class NotLockedError(AuthError):
    """Raised when operation requires locked state."""

    pass


class AlreadyLockedError(AuthError):
    """Raised when operation requires unlocked state."""

    pass


class SessionExpiredError(AuthError):
    """Raised when session has expired."""

    pass


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class SessionState:
    """
    Current session state.

    Attributes:
        is_locked: Whether session is currently locked
        unlocked_at: Timestamp when session was unlocked
        last_activity: Timestamp of last activity
        auto_lock_timeout: Auto-lock timeout in seconds
    """

    is_locked: bool = True
    unlocked_at: Optional[float] = None
    last_activity: Optional[float] = None
    auto_lock_timeout: int = 300  # 5 minutes

    @property
    def time_since_activity(self) -> Optional[float]:
        """Time since last activity in seconds."""
        if self.last_activity is None:
            return None
        return time.time() - self.last_activity

    @property
    def time_since_unlock(self) -> Optional[float]:
        """Time since unlock in seconds."""
        if self.unlocked_at is None:
            return None
        return time.time() - self.unlocked_at

    def is_expired(self) -> bool:
        """Check if session has expired due to inactivity."""
        if self.is_locked:
            return False
        if self.time_since_activity is None:
            return False
        return self.time_since_activity > self.auto_lock_timeout


# =============================================================================
# AuthManager Class
# =============================================================================


class AuthManager:
    """
    Authentication Manager - manages master key and session state.

    Features:
    - Wrapped master key storage (plaintext key material is short-lived)
    - Auto-lock timer with background thread
    - Activity tracking
    - Callback support for lock events
    - Ephemeral key lifecycle via context manager

    Thread-safe: All public methods are thread-safe.

    Example:
        >>> crypto = CryptoCore()
        >>> auth = AuthManager(crypto)

        # Unlock with password
        >>> auth.unlock("my_password", salt)

        # Use the key via context manager (recommended)
        >>> with auth.with_master_key() as key:
        ...     encrypted = crypto.encrypt(data, bytes(key))
        # key is automatically zeroed here

        # Lock when done
        >>> auth.lock()
    """

    def __init__(
        self,
        crypto: CryptoCore,
        auto_lock_timeout: int = 300,
        on_lock: Optional[Callable[[], None]] = None,
        on_unlock: Optional[Callable[[], None]] = None,
        master_key_provider: Optional[Callable[[], bytes]] = None,
        retain_master_key_in_session: bool = True,
    ):
        """
        Initialize AuthManager.

        Args:
            crypto: CryptoCore instance for key derivation
            auto_lock_timeout: Auto-lock timeout in seconds (default: 300 = 5 min)
            on_lock: Optional callback when session locks
            on_unlock: Optional callback when session unlocks
            master_key_provider: Optional provider for ephemeral master key mode
            retain_master_key_in_session: If False, do not retain wrapped session key material

        Raises:
            ValueError: If auto_lock_timeout < 60 seconds
        """
        if auto_lock_timeout < 60:
            raise ValueError("auto_lock_timeout must be at least 60 seconds")
        if not retain_master_key_in_session and master_key_provider is None:
            raise ValueError(
                "master_key_provider is required when retain_master_key_in_session is False"
            )

        self._crypto = crypto
        self._auto_lock_timeout = auto_lock_timeout
        self._on_lock = on_lock
        self._on_unlock = on_unlock
        self._master_key_provider = master_key_provider
        self._retain_master_key_in_session = retain_master_key_in_session

        # Master key storage for unlocked sessions:
        # - retain_master_key_in_session=True:
        #   _wrapped_master_key + _session_wrap_key are kept until lock().
        # - retain_master_key_in_session=False:
        #   no key material is retained in AuthManager state.
        #   plaintext key is requested from master_key_provider only per operation.
        self._wrapped_master_key: Optional[bytes] = None
        self._session_wrap_key: Optional[bytearray] = None

        # Session state
        self._state = SessionState(auto_lock_timeout=auto_lock_timeout)

        # Thread safety
        self._lock = threading.RLock()

        # Auto-lock timer
        self._timer: Optional[threading.Timer] = None
        self._timer_lock = threading.Lock()

    # ==========================================================================
    # Properties
    # ==========================================================================

    @property
    def is_locked(self) -> bool:
        """Check if session is locked."""
        with self._lock:
            return self._state.is_locked

    @property
    def is_unlocked(self) -> bool:
        """Check if session is unlocked."""
        with self._lock:
            return not self._state.is_locked

    @property
    def auto_lock_timeout(self) -> int:
        """Get auto-lock timeout in seconds."""
        return self._auto_lock_timeout

    @property
    def time_since_activity(self) -> Optional[float]:
        """Get time since last activity in seconds."""
        with self._lock:
            return self._state.time_since_activity

    @property
    def time_until_auto_lock(self) -> Optional[float]:
        """Get time until auto-lock in seconds."""
        with self._lock:
            if self._state.is_locked:
                return None
            elapsed = self._state.time_since_activity or 0
            remaining = self._auto_lock_timeout - elapsed
            return max(0, remaining)

    # ==========================================================================
    # Lock/Unlock Methods
    # ==========================================================================

    def unlock(self, password: str, salt: bytes) -> None:
        """
        Unlock session with password.

        Derives master key from password and stores it in wrapped form.
        Starts auto-lock timer.

        Args:
            password: User password
            salt: Salt for key derivation

        Raises:
            ValueError: If password is empty or salt too short
            AlreadyLockedError: If session is already unlocked

        Example:
            >>> auth.unlock("my_password", salt)
            >>> assert auth.is_unlocked
        """
        if not password:
            raise ValueError("Password cannot be empty")

        if len(salt) < 8:
            raise ValueError("Salt must be at least 8 bytes")

        with self._lock:
            if not self._state.is_locked:
                raise AlreadyLockedError("Session is already unlocked")

            if self._retain_master_key_in_session:
                # Derive plaintext key only transiently, then wrap it for in-memory storage.
                derived_master_key = bytearray(
                    self._crypto.derive_master_key(password, salt)
                )
                wrap_key = bytearray(
                    self._crypto.generate_random_bytes(self._crypto.config.key_size)
                )
                wrap_key_stored = False
                try:
                    self._wrapped_master_key = self._crypto.encrypt(
                        bytes(derived_master_key),
                        bytes(wrap_key),
                    )
                    self._session_wrap_key = wrap_key
                    wrap_key_stored = True
                finally:
                    if not wrap_key_stored:
                        zero_memory(wrap_key)
                    zero_memory(derived_master_key)
            else:
                # Ephemeral mode: verify credentials once, but keep no key material in session state.
                derived_master_key = bytearray(
                    self._crypto.derive_master_key(password, salt)
                )
                provider_key = self._get_provider_key()
                try:
                    if not self._crypto.constant_time_compare(
                        bytes(provider_key), bytes(derived_master_key)
                    ):
                        raise AuthError(
                            "master_key_provider returned key material that does not match unlock credentials"
                        )
                finally:
                    zero_memory(provider_key)
                    zero_memory(derived_master_key)
                self._wrapped_master_key = None
                self._session_wrap_key = None

            # Update state
            self._state.is_locked = False
            self._state.unlocked_at = time.time()
            self._state.last_activity = time.time()

            # Start auto-lock timer
            self._start_auto_lock_timer()

            # Callback
            if self._on_unlock:
                self._on_unlock()

    def lock(self) -> None:
        """
        Lock session and zero master key from memory.

        Securely erases master key from memory.
        Stops auto-lock timer.

        Raises:
            NotLockedError: If session is already locked

        Example:
            >>> auth.lock()
            >>> assert auth.is_locked
        """
        with self._lock:
            if self._state.is_locked:
                raise NotLockedError("Session is already locked")

            # Stop auto-lock timer
            self._stop_auto_lock_timer()

            # Zero wrapping key and clear wrapped payload.
            if self._session_wrap_key is not None:
                zero_memory(self._session_wrap_key)
                self._session_wrap_key = None
            self._wrapped_master_key = None

            # Update state
            self._state.is_locked = True
            self._state.unlocked_at = None
            self._state.last_activity = None

            # Callback
            if self._on_lock:
                self._on_lock()

    def touch(self) -> None:
        """
        Update last activity timestamp.

        Call this method when user performs any action to reset
        the auto-lock timer.

        Example:
            >>> auth.touch()  # User clicked something
            >>> time.sleep(10)
            >>> auth.touch()  # Reset timer
        """
        with self._lock:
            if not self._state.is_locked:
                self._state.last_activity = time.time()
                # Restart timer
                self._start_auto_lock_timer()

    # ==========================================================================
    # Key Access Methods — Ephemeral Key Lifecycle
    # ==========================================================================

    @contextmanager
    def with_master_key(self) -> Iterator[bytearray]:
        """
        Context manager for ephemeral master key access.

        Derives or unwraps the master key, yields it for a single
        operation, and immediately zeros it on exit — regardless
        of whether the operation succeeded or raised an exception.

        This is the SAFEST way to access the master key.

        Yields:
            bytearray: Plaintext master key (32 bytes)

        Raises:
            AlreadyLockedError: If session is locked

        Example:
            >>> with auth.with_master_key() as key:
            ...     encrypted = crypto.encrypt(data, bytes(key))
            # key is automatically zeroed here
        """
        with self._lock:
            if self._state.is_locked:
                raise AlreadyLockedError("Session is locked")

            if self._retain_master_key_in_session:
                if self._wrapped_master_key is None or self._session_wrap_key is None:
                    raise AlreadyLockedError("Master key not available")

                unwrapped = self._crypto.decrypt(
                    self._wrapped_master_key,
                    bytes(self._session_wrap_key),
                )
                key_buffer = bytearray(unwrapped)
                del unwrapped
            else:
                key_buffer = self._get_provider_key()

        try:
            yield key_buffer
        finally:
            zero_memory(key_buffer)

    @contextmanager
    def with_derived_key(self, context: bytes) -> Iterator[bytearray]:
        """
        Context manager for ephemeral derived subkey access.

        Derives a subkey for a specific purpose (encryption, HMAC, etc.),
        yields it for a single operation, and immediately zeros it on exit.

        Args:
            context: Context for key derivation (e.g., b"encryption")

        Yields:
            bytearray: Derived subkey (32 bytes)

        Raises:
            AlreadyLockedError: If session is locked

        Example:
            >>> with auth.with_derived_key(b"encryption") as key:
            ...     encrypted = crypto.encrypt(data, bytes(key))
            # key is automatically zeroed here
        """
        with self._lock:
            if self._state.is_locked:
                raise AlreadyLockedError("Session is locked")

            if self._retain_master_key_in_session:
                if self._wrapped_master_key is None or self._session_wrap_key is None:
                    raise AlreadyLockedError("Master key not available")

                unwrapped = self._crypto.decrypt(
                    self._wrapped_master_key,
                    bytes(self._session_wrap_key),
                )
                master_key = bytearray(unwrapped)
                del unwrapped
            else:
                master_key = self._get_provider_key()

        try:
            subkey = bytearray(self._crypto.derive_subkey(bytes(master_key), context))
            yield subkey
        finally:
            zero_memory(master_key)
            if "subkey" in dir():
                zero_memory(subkey)

    def _get_provider_key(self) -> bytearray:
        """Resolve and validate provider key for ephemeral mode operations."""
        if self._master_key_provider is None:
            raise AuthError(
                "master_key_provider is not configured for ephemeral session mode"
            )
        provided = self._master_key_provider()
        if not isinstance(provided, (bytes, bytearray)):
            raise AuthError("master_key_provider must return bytes")
        key_buffer = bytearray(provided)
        if len(key_buffer) != self._crypto.config.key_size:
            zero_memory(key_buffer)
            raise AuthError(
                f"master_key_provider returned invalid key length: expected {self._crypto.config.key_size}"
            )
        return key_buffer

    def get_master_key(self) -> bytearray:
        """
        Get copy of master key for cryptographic operations.

        DEPRECATED: Use `with_master_key()` context manager instead.
        This method returns a copy that the caller must zero manually.

        Returns:
            Copy of master key as bytearray (32 bytes)

        Raises:
            AlreadyLockedError: If session is locked

        Important:
            Caller is responsible for zeroing the returned key after use!
            Use zero_memory() to securely erase the key.

        Example:
            >>> key = auth.get_master_key()
            >>> try:
            ...     encrypted = crypto.encrypt(data, bytes(key))
            ... finally:
            ...     zero_memory(key)
        """
        with self._lock:
            with self.with_master_key() as master_key:
                # Return a copy as bytearray for secure zeroing by caller.
                return bytearray(master_key)

    def get_derived_key(self, context: bytes) -> bytearray:
        """
        Get derived subkey for specific purpose.

        DEPRECATED: Use `with_derived_key()` context manager instead.
        This method returns a copy that the caller must zero manually.

        Args:
            context: Context for key derivation (e.g., b"encryption")

        Returns:
            Derived subkey as bytearray (32 bytes)

        Raises:
            AlreadyLockedError: If session is locked

        Important:
            Caller is responsible for zeroing the returned key after use!

        Example:
            >>> enc_key = auth.get_derived_key(b"encryption")
            >>> try:
            ...     encrypted = crypto.encrypt(data, bytes(enc_key))
            ... finally:
            ...     zero_memory(enc_key)
        """
        with self._lock:
            with self.with_derived_key(context) as subkey:
                return bytearray(subkey)

    # ==========================================================================
    # Auto-Lock Timer
    # ==========================================================================

    def _start_auto_lock_timer(self) -> None:
        """Start or restart auto-lock timer."""
        with self._timer_lock:
            # Stop existing timer
            if self._timer is not None:
                self._timer.cancel()

            # Create new timer
            self._timer = threading.Timer(
                self._auto_lock_timeout,
                self._auto_lock_callback,
            )
            self._timer.daemon = True
            self._timer.start()

    def _stop_auto_lock_timer(self) -> None:
        """Stop auto-lock timer."""
        with self._timer_lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _auto_lock_callback(self) -> None:
        """Callback for auto-lock timer."""
        with self._lock:
            if self._state.is_expired():
                # Lock in a separate thread to avoid deadlock
                threading.Thread(target=self.lock).start()

    # ==========================================================================
    # Context Manager
    # ==========================================================================

    def __enter__(self) -> "AuthManager":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Literal[False]:
        """Context manager exit - ensures session is locked."""
        if self.is_unlocked:
            self.lock()
        return False

    # ==========================================================================
    # String Representation
    # ==========================================================================

    def __repr__(self) -> str:
        status = "unlocked" if self.is_unlocked else "locked"
        return f"<AuthManager status={status}>"


# =============================================================================
# Session Manager (Multiple Sessions)
# =============================================================================


@dataclass
class SessionInfo:
    """Information about a session."""

    session_id: str
    created_at: float
    last_activity: float
    is_active: bool = True


class SessionManager:
    """
    Manages multiple user sessions.

    Features:
    - Create/destroy sessions
    - Session expiration
    - Active session tracking

    Example:
        >>> session_mgr = SessionManager()
        >>> session_id = session_mgr.create_session()
        >>> session_mgr.destroy_session(session_id)
    """

    def __init__(self, max_sessions_per_user: int = 5):
        """
        Initialize SessionManager.

        Args:
            max_sessions_per_user: Maximum concurrent sessions per user
        """
        self._max_sessions = max_sessions_per_user
        self._sessions: dict[str, SessionInfo] = {}
        self._lock = threading.Lock()

    def create_session(self, user_id: str) -> str:
        """
        Create new session for user.

        Args:
            user_id: User identifier

        Returns:
            Session ID

        Raises:
            ValueError: If max sessions exceeded
        """
        import secrets

        with self._lock:
            # Count active sessions for user
            active_count = sum(1 for s in self._sessions.values() if s.is_active)

            if active_count >= self._max_sessions:
                raise ValueError(f"Maximum {self._max_sessions} sessions allowed")

            # Create session
            session_id = secrets.token_urlsafe(32)
            now = time.time()

            self._sessions[session_id] = SessionInfo(
                session_id=session_id,
                created_at=now,
                last_activity=now,
                is_active=True,
            )

            return session_id

    def destroy_session(self, session_id: str) -> bool:
        """
        Destroy session.

        Args:
            session_id: Session ID to destroy

        Returns:
            True if session was destroyed, False if not found
        """
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].is_active = False
                return True
            return False

    def touch_session(self, session_id: str) -> bool:
        """
        Update session last activity.

        Args:
            session_id: Session ID

        Returns:
            True if session exists and is active
        """
        with self._lock:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                if session.is_active:
                    session.last_activity = time.time()
                    return True
            return False

    def is_session_valid(self, session_id: str) -> bool:
        """
        Check if session is valid and active.

        Args:
            session_id: Session ID

        Returns:
            True if session is valid
        """
        with self._lock:
            if session_id not in self._sessions:
                return False

            session = self._sessions[session_id]
            return session.is_active

    def get_active_sessions(self) -> list[SessionInfo]:
        """
        Get all active sessions.

        Returns:
            List of active session info
        """
        with self._lock:
            return [s for s in self._sessions.values() if s.is_active]


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Exceptions
    "AuthError",
    "NotLockedError",
    "AlreadyLockedError",
    "SessionExpiredError",
    # Main classes
    "AuthManager",
    "SessionManager",
    "SessionState",
    "SessionInfo",
]
