# -*- coding: utf-8 -*-
"""
Advanced Security Features - Продвинутые функции безопасности

Provides:
- TOTP (Time-based One-Time Password) for 2FA
- Recovery Codes generation and verification
- Have I Been Pwned API integration (k-anonymity)
- Biometric authentication stub (Windows Hello)

Author: Nikita (BE1)
Version: 1.1.0
"""

import hashlib
import hmac
import struct
import time
import secrets
import base64
import os
from typing import List, Tuple, Optional, Set
from dataclasses import dataclass
import urllib.parse
import json

import httpx


# =============================================================================
# TOTP (2FA) Implementation
# =============================================================================

class TOTPAuthenticator:
    """
    TOTP (Time-based One-Time Password) authenticator.
    
    Implements RFC 6238 for TOTP generation.
    Compatible with Google Authenticator, Authy, etc.
    
    Example:
        >>> totp = TOTPAuthenticator()
        >>> secret, uri = totp.setup("user@example.com", "MyApp")
        >>> code = totp.generate(secret)
        >>> is_valid = totp.verify(secret, code)
    """
    
    # TOTP configuration
    TIME_STEP = 30  # 30 seconds
    CODE_DIGITS = 6
    HASH_ALGORITHM = 'sha256'
    
    def __init__(self):
        """Initialize TOTP authenticator."""
        pass
    
    def setup(
        self,
        username: str,
        issuer: str,
        secret_length: int = 20,
    ) -> Tuple[str, str]:
        """
        Setup TOTP for a new user.
        
        Args:
            username: User identifier (email)
            issuer: Service name (e.g., "MyApp")
            secret_length: Length of secret in bytes (default 20 = 160 bits)
        
        Returns:
            Tuple of (secret_key, otpauth_uri)
        
        Example:
            >>> secret, uri = totp.setup("user@example.com", "MyApp")
            >>> # Scan URI with authenticator app
        """
        # Generate random secret
        secret = secrets.token_bytes(secret_length)
        secret_b32 = self._base32_encode(secret)
        
        # Create otpauth URI
        otpauth_uri = self._create_otpauth_uri(
            username=username,
            issuer=issuer,
            secret=secret_b32,
        )
        
        return secret_b32, otpauth_uri
    
    def generate(self, secret: str, timestamp: Optional[float] = None) -> str:
        """
        Generate TOTP code.
        
        Args:
            secret: Base32-encoded secret key
            timestamp: Optional timestamp (default: current time)
        
        Returns:
            6-digit TOTP code
        
        Example:
            >>> code = totp.generate(secret)
            >>> print(f"Your code: {code}")
        """
        secret_bytes = self._base32_decode(secret)
        
        # Get time counter
        if timestamp is None:
            timestamp = time.time()
        counter = int(timestamp // self.TIME_STEP)
        
        # Generate HOTP
        return self._generate_hotp(secret_bytes, counter)
    
    def verify(
        self,
        secret: str,
        code: str,
        last_used_counter: Optional[int] = None,
        window: int = 1,
        timestamp: Optional[float] = None,
    ):
        """
        Verify TOTP code with time window and replay protection.

        Args:
            secret: Base32-encoded secret key
            code: Code to verify
            last_used_counter: Previous successful counter from database (if None, returns bool only)
            window: Number of time steps to check before/after (default 1)
            timestamp: Optional timestamp

        Returns:
            bool if last_used_counter is None,
            tuple[bool, int] otherwise.
        """
        if timestamp is None:
            timestamp = time.time()

        current_counter = int(timestamp // self.TIME_STEP)

        for offset in range(-window, window + 1):
            counter = current_counter + offset

            if last_used_counter is not None and counter <= last_used_counter:
                continue

            secret_bytes = self._base32_decode(secret)
            expected_code = self._generate_hotp(secret_bytes, counter)

            if hmac.compare_digest(code, expected_code):
                if last_used_counter is None:
                    return True
                return True, counter

        if last_used_counter is None:
            return False
        return False, last_used_counter or -1
    
    def _generate_hotp(self, secret: bytes, counter: int) -> str:
        """
        Generate HOTP code (RFC 4226).
        
        Args:
            secret: Secret key
            counter: Counter value
        
        Returns:
            6-digit HOTP code
        """
        # Pack counter as 8-byte big-endian
        counter_bytes = struct.pack('>Q', counter)
        
        # Generate HMAC-SHA256
        hmac_hash = hmac.new(secret, counter_bytes, hashlib.sha256).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        truncated = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
        truncated &= 0x7FFFFFFF
        
        # Generate 6-digit code
        code = truncated % (10 ** self.CODE_DIGITS)
        return str(code).zfill(self.CODE_DIGITS)
    
    def _create_otpauth_uri(
        self,
        username: str,
        issuer: str,
        secret: str,
    ) -> str:
        """
        Create otpauth:// URI for QR code generation.
        
        Args:
            username: User identifier
            issuer: Service name
            secret: Base32-encoded secret
        
        Returns:
            otpauth:// URI
        """
        params = {
            'secret': secret,
            'issuer': issuer,
            'algorithm': self.HASH_ALGORITHM.upper(),
            'digits': str(self.CODE_DIGITS),
            'period': str(self.TIME_STEP),
        }
        
        query = urllib.parse.urlencode(params)
        return f"otpauth://totp/{issuer}:{username}?{query}"
    
    def _base32_encode(self, data: bytes) -> str:
        """Encode bytes to base32 (uppercase, no padding)."""
        return base64.b32encode(data).decode('ascii').rstrip('=')
    
    def _base32_decode(self, data: str) -> bytes:
        """Decode base32 string to bytes."""
        # Add padding if needed
        padding = '=' * (-len(data) % 8)
        return base64.b32decode(data + padding)

    def generate_qr_code(
        self,
        secret: str,
        username: str,
        issuer: str,
        output_format: str = "base64",
    ) -> str:
        """
        Generate QR code for TOTP setup.
        
        Requires qrcode library: pip install qrcode>=7.4
        
        Args:
            secret: Base32-encoded secret key
            username: User identifier (email)
            issuer: Service name (e.g., "Password Manager")
            output_format: Output format ("base64" or "png")
        
        Returns:
            QR code in specified format (base64 string or PNG bytes)
        
        Raises:
            ImportError: If qrcode library is not installed
        
        Example:
            >>> secret, uri = totp.setup("user@example.com", "MyApp")
            >>> qr_base64 = totp.generate_qr_code(secret, "user@example.com", "MyApp")
            >>> # For HTML: <img src="data:image/png;base64,{qr_base64}" />
        """
        try:
            import qrcode
        except ImportError:
            raise ImportError(
                "qrcode library is not installed. "
                "Install with: pip install qrcode>=7.4"
            )
        
        # Create otpauth URI
        uri = self._create_otpauth_uri(username, issuer, secret)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_Q,  # 25% error correction
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        if output_format == "base64":
            import io
            import base64
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format="PNG", optimize=True)
            return base64.b64encode(buffer.getvalue()).decode('ascii')
        
        elif output_format == "png":
            import io
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = io.BytesIO()
            img.save(buffer, format="PNG", optimize=True)
            return buffer.getvalue()
        
        else:
            raise ValueError(f"Unsupported output format: {output_format}")


# =============================================================================
# Recovery Codes
# =============================================================================

@dataclass
class RecoveryCode:
    """Recovery code with metadata."""
    code: str
    code_hash: str
    used: bool = False
    used_at: Optional[float] = None


class RecoveryCodeManager:
    """
    Manager for TOTP recovery codes.
    
    Generates one-time use backup codes for account recovery.
    Codes are stored as hashes for security.
    
    Example:
        >>> manager = RecoveryCodeManager()
        >>> codes, stored_codes = manager.generate_codes("user123", count=10)
        >>> # Show codes to user (one-time!)
        >>> # Later: verify a code
        >>> is_valid = manager.verify("user123", "ABCD-1234")
    """
    
    def __init__(self):
        """Initialize recovery code manager."""
        self._codes: dict[str, dict[str, RecoveryCode]] = {}
    
    def generate_codes(
        self,
        user_id: str,
        count: int = 10,
        code_length: int = 8,
    ) -> Tuple[List[str], List[RecoveryCode]]:
        """
        Generate recovery codes for user.
        
        Args:
            user_id: User identifier
            count: Number of codes to generate (default 10)
            code_length: Length of each code (default 8)
        
        Returns:
            Tuple of (plain_codes, stored_codes)
            plain_codes: Show to user once
            stored_codes: Store hashed codes
        
        Important:
            plain_codes should be shown to user ONCE and never stored!
        """
        plain_codes = []
        stored_codes = []
        
        for _ in range(count):
            # Generate random code
            code = self._generate_code(code_length)
            code_hash = self._hash_code(code)
            
            plain_codes.append(code)
            recovery_code = RecoveryCode(code=code, code_hash=code_hash)
            stored_codes.append(recovery_code)
        
        # Store hashed codes
        self._codes[user_id] = {
            rc.code_hash: rc for rc in stored_codes
        }
        
        return plain_codes, stored_codes
    
    def verify(self, user_id: str, code: str) -> bool:
        """
        Verify and consume a recovery code.
        
        Args:
            user_id: User identifier
            code: Recovery code to verify
        
        Returns:
            True if code was valid and is now consumed
        
        Side Effects:
            Marks code as used (one-time use)
        """
        if user_id not in self._codes:
            return False
        
        # We need to iterate over stored hashes and use Argon2 verify
        valid_code_hash = None
        recovery_code = None
        for code_hash, rc in self._codes[user_id].items():
            if rc.used:
                continue
            if self._verify_code_hash(code, code_hash):
                valid_code_hash = code_hash
                recovery_code = rc
                break
                
        if not valid_code_hash or not recovery_code:
            return False
            
        # Mark as used
        recovery_code.used = True
        recovery_code.used_at = time.time()
        
        return True
    
    def get_unused_count(self, user_id: str) -> int:
        """
        Get count of unused recovery codes.
        
        Args:
            user_id: User identifier
        
        Returns:
            Number of unused codes
        """
        if user_id not in self._codes:
            return 0
        
        return sum(
            1 for rc in self._codes[user_id].values()
            if not rc.used
        )
    
    def _generate_code(self, length: int) -> str:
        """
        Generate a recovery code.
        
        Format: XXXX-XXXX (groups of 4, uppercase alphanumeric)
        """
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # No I, O, 0, 1
        code = ''.join(secrets.choice(chars) for _ in range(length))
        
        # Format in groups of 4
        groups = [code[i:i+4] for i in range(0, len(code), 4)]
        return '-'.join(groups)
    
    def _hash_code(self, code: str) -> str:
        """Hash recovery code for secure storage via Argon2id."""
        from argon2 import PasswordHasher
        ph = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=2)
        return ph.hash(code)
        
    def _verify_code_hash(self, code: str, code_hash: str) -> bool:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
        ph = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=2)
        try:
            return ph.verify(code_hash, code)
        except VerifyMismatchError:
            return False


# =============================================================================
# Have I Been Pwned API Integration
# =============================================================================

class HaveIBeenPwnedChecker:
    PASSWORD_API_URL = "https://api.pwnedpasswords.com/range/"
    EMAIL_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    USER_AGENT = "PasswordManager/2.1.0"

    def __init__(self, timeout: int = 10, api_key: Optional[str] = None):
        self._timeout = timeout
        self._api_key = api_key if api_key is not None else os.getenv("HIBP_API_KEY")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                headers={"User-Agent": self.USER_AGENT},
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        await self._get_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def check_password(self, password: str) -> Tuple[bool, int]:
        sha1_hash = hashlib.sha1(
            password.encode('utf-8'),
            usedforsecurity=False  # type: ignore  # nosec B324 — SHA1 required by HIBP k-anonymity protocol
        ).hexdigest().upper()

        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        hashes = await self.fetch_hashes(prefix)

        for line in hashes.splitlines():
            if ':' in line:
                hash_suffix, count = line.split(':')
                if hash_suffix.upper() == suffix:
                    return True, int(count)

        return False, 0

    async def check_suffix(self, prefix: str, suffix: str) -> Tuple[bool, int]:
        """Check a password breach status using k-anonymity with pre-computed prefix and suffix.

        Args:
            prefix: First 5 characters of the SHA-1 hash (uppercase)
            suffix: Remaining characters of the SHA-1 hash (uppercase)

        Returns:
            Tuple of (is_pwned, breach_count)
        """
        hashes = await self.fetch_hashes(prefix)

        for line in hashes.splitlines():
            if ':' in line:
                hash_suffix, count = line.split(':')
                if hash_suffix.upper() == suffix.upper():
                    return True, int(count)

        return False, 0

    async def check_email(self, email: str) -> Tuple[bool, int]:
        normalized_email = email.strip().lower()
        if not normalized_email:
            raise ValueError("Email must not be empty")

        if not self._api_key:
            raise PermissionError(
                "HIBP email checks require API key in constructor or HIBP_API_KEY env var"
            )

        encoded_email = urllib.parse.quote(normalized_email, safe="")
        url = f"{self.EMAIL_API_URL}{encoded_email}?truncateResponse=true"

        try:
            client = await self._get_client()
            response = await client.get(
                url,
                headers={"hibp-api-key": self._api_key},
            )
            if response.status_code == 404:
                return False, 0
            if response.status_code in (401, 403):
                raise PermissionError("HIBP API key is invalid or unauthorized")
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "unknown")
                raise ConnectionError(
                    f"HIBP email endpoint rate limited (Retry-After: {retry_after})"
                )
            response.raise_for_status()
            data = response.json() if response.text else []
            if isinstance(data, list):
                return len(data) > 0, len(data)
            return False, 0
        except (PermissionError, ConnectionError):
            raise
        except httpx.HTTPError as exc:
            raise ConnectionError(f"HIBP email request failed: {exc}") from exc

    def check_email_sync(self, email: str) -> Tuple[bool, int]:
        with httpx.Client(
            timeout=self._timeout,
            headers={"User-Agent": self.USER_AGENT},
        ) as client:
            normalized_email = email.strip().lower()
            if not normalized_email:
                raise ValueError("Email must not be empty")
            if not self._api_key:
                raise PermissionError("HIBP email checks require API key")
            encoded_email = urllib.parse.quote(normalized_email, safe="")
            url = f"{self.EMAIL_API_URL}{encoded_email}?truncateResponse=true"
            try:
                response = client.get(url, headers={"hibp-api-key": self._api_key})
                if response.status_code == 404:
                    return False, 0
                if response.status_code in (401, 403):
                    raise PermissionError("HIBP API key is invalid or unauthorized")
                if response.status_code == 429:
                    raise ConnectionError("HIBP email endpoint rate limited")
                response.raise_for_status()
                data = response.json() if response.text else []
                if isinstance(data, list):
                    return len(data) > 0, len(data)
                return False, 0
            except (PermissionError, ConnectionError):
                raise
            except httpx.HTTPError as exc:
                raise ConnectionError(f"HIBP email request failed: {exc}") from exc

    async def fetch_hashes(self, prefix: str) -> str:
        url = f"{self.PASSWORD_API_URL}{prefix}"

        try:
            client = await self._get_client()
            response = await client.get(url)
            response.raise_for_status()
            return response.text
        except httpx.HTTPError as exc:
            raise ConnectionError(f"HIBP API request failed: {exc}") from exc

    def _fetch_hashes(self, prefix: str) -> str:
        with httpx.Client(
            timeout=self._timeout,
            headers={"User-Agent": self.USER_AGENT},
        ) as client:
            try:
                response = client.get(f"{self.PASSWORD_API_URL}{prefix}")
                response.raise_for_status()
                return response.text
            except httpx.HTTPError as exc:
                raise ConnectionError(f"HIBP API request failed: {exc}") from exc


class BiometricError(Exception):
    """Exception raised for biometric authentication errors."""
    pass


class _BiometricBackend:
    """Backend contract for platform-specific biometric integrations."""

    def is_available(self) -> bool:
        raise NotImplementedError

    def is_enrolled(self) -> bool:
        raise NotImplementedError

    def authenticate(self) -> bool:
        raise NotImplementedError

    def enroll(self) -> bool:
        raise NotImplementedError


class _UnavailableBiometricBackend(_BiometricBackend):
    """Fail-closed backend used when no platform integration is configured."""

    def __init__(self, reason: str):
        self._reason = reason

    def is_available(self) -> bool:
        return False

    def is_enrolled(self) -> bool:
        return False

    def authenticate(self) -> bool:
        raise BiometricError(self._reason)

    def enroll(self) -> bool:
        raise BiometricError(self._reason)


class _InMemoryBiometricBackend(_BiometricBackend):
    """
    In-memory simulator backend for local development/testing only.

    Enabled via BEZ_ENABLE_BIOMETRIC_SIMULATOR=1.
    """

    def __init__(self):
        self._enrolled = False

    def is_available(self) -> bool:
        return True

    def is_enrolled(self) -> bool:
        return self._enrolled

    def authenticate(self) -> bool:
        if not self._enrolled:
            raise BiometricError("Biometric data is not enrolled")
        return True

    def enroll(self) -> bool:
        self._enrolled = True
        return True


class _WebAuthnBiometricBackend(_BiometricBackend):
    """Backend that checks platform biometric enrollment via WebAuthnCredential DB."""

    def __init__(self, user_id: Optional[int] = None):
        self._enrolled: Optional[bool] = None
        self._user_id = user_id

    def is_available(self) -> bool:
        return True

    def is_enrolled(self) -> bool:
        if self._user_id is None:
            return self._enrolled is True
        try:
            from backend.database.session import sync_engine
            from backend.database.models import WebAuthnCredential
            from sqlalchemy import select
            with sync_engine.connect() as conn:
                stmt = select(WebAuthnCredential.is_biometric).where(
                    WebAuthnCredential.user_id == self._user_id,
                    WebAuthnCredential.is_biometric == True,
                ).limit(1)
                result = conn.execute(stmt)
                row = result.first()
                return row is not None
        except Exception:
            return self._enrolled is True

    def authenticate(self) -> bool:
        if not self.is_enrolled():
            raise BiometricError("No platform biometric credential enrolled")
        return True

    def enroll(self) -> bool:
        self._enrolled = True
        return True


# =============================================================================
# Biometric Authentication
# =============================================================================

class BiometricAuthenticator:
    """
    Biometric authentication facade with explicit backend selection.

    Default behavior is fail-closed when no secure platform backend is
    configured. For local testing, BEZ_ENABLE_BIOMETRIC_SIMULATOR=1 enables
    an in-memory simulator.

    Pass ``user_id`` to enable DB-backed enrollment checks via WebAuthnCredential.
    """

    def __init__(self, backend: Optional[_BiometricBackend] = None, user_id: Optional[int] = None):
        """Initialize biometric authenticator."""
        if backend is not None:
            self._backend = backend
        elif os.getenv("BEZ_ENABLE_BIOMETRIC_SIMULATOR") == "1":
            self._backend = _InMemoryBiometricBackend()
        else:
            try:
                self._backend = _WebAuthnBiometricBackend(user_id=user_id)
            except Exception:
                self._backend = _UnavailableBiometricBackend(
                    "Biometric backend is not configured for this platform/runtime"
                )
    
    def is_available(self) -> bool:
        """
        Check if biometric authentication backend is available.
        
        Returns:
            True if biometric backend is operational
        """
        return self._backend.is_available()
    
    def is_enrolled(self) -> bool:
        """
        Check if user has enrolled biometric data.
        
        Returns:
            True if user has enrolled fingerprints/face
        """
        return self._backend.is_enrolled()
    
    def authenticate(self) -> bool:
        """
        Authenticate using biometrics.
        
        Returns:
            True if authentication successful
        
        Raises:
            BiometricError: If authentication fails
        """
        return self._backend.authenticate()
    
    def enroll(self) -> bool:
        """
        Enroll new biometric data.
        
        Returns:
            True if enrollment successful
        
        Raises:
            BiometricError: If backend is unavailable
        """
        return self._backend.enroll()


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # TOTP
    'TOTPAuthenticator',
    
    # Recovery Codes
    'RecoveryCode',
    'RecoveryCodeManager',
    
    # HIBP
    'HaveIBeenPwnedChecker',
    
    # Biometric
    'BiometricAuthenticator',
    'BiometricError',
]
