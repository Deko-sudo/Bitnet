# -*- coding: utf-8 -*-
"""
Security Utils - Security Utilities

Provides:
- Rate Limiter (brute-force protection)
- Password Strength Checker
- Entropy calculation

Author: Nikita (BE1)
Version: 2.0
"""

import time
import math
import threading
import re
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import IntEnum

from .config import RateLimitConfig, PasswordStrengthConfig


# =============================================================================
# Password Strength Enums
# =============================================================================


class PasswordStrength(IntEnum):
    """Password strength levels."""

    VERY_WEAK = 0
    WEAK = 1
    FAIR = 2
    GOOD = 3
    STRONG = 4


@dataclass
class PasswordStrengthResult:
    """
    Password strength assessment result.

    Attributes:
        strength: PasswordStrength enum value
        entropy_bits: Calculated entropy in bits
        crack_time_estimate: Estimated crack time (human-readable)
        has_uppercase: Has uppercase letters
        has_lowercase: Has lowercase letters
        has_digits: Has digits
        has_special: Has special characters
        length: Password length
        suggestions: List of improvement suggestions
    """

    strength: PasswordStrength
    entropy_bits: float
    crack_time_estimate: str
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    length: int
    suggestions: list[str] = field(default_factory=list)


# =============================================================================
# Rate Limiter
# =============================================================================


class RateLimiter:
    """
    Rate Limiter for brute-force protection.

    Implements exponential backoff after failed attempts.

    Features:
    - Track failed attempts per identifier (IP, user, etc.)
    - Exponential backoff delay
    - Automatic reset after success
    - Thread-safe

    Example:
        >>> limiter = RateLimiter()

        # Check if attempt is allowed
        >>> if limiter.can_attempt("user123"):
        ...     # Try authentication
        ...     if auth_failed:
        ...         limiter.register_failed("user123")
        ...     else:
        ...         limiter.register_success("user123")
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 60,
        block_duration_seconds: int = 1800,
        exponential_base: float = 2.0,
        max_delay_seconds: int = 60,
    ):
        """
        Initialize RateLimiter.

        Args:
            max_attempts: Maximum attempts before blocking
            window_seconds: Time window for counting attempts
            block_duration_seconds: Block duration after max attempts
            exponential_base: Base for exponential backoff
            max_delay_seconds: Maximum delay between attempts
        """
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._block_duration = block_duration_seconds
        self._exponential_base = exponential_base
        self._max_delay = max_delay_seconds

        # Storage: identifier -> {attempts: [], blocked_until: float}
        self._storage: Dict[str, dict] = {}
        self._lock = threading.RLock()

    def can_attempt(self, identifier: str) -> bool:
        """
        Check if attempt is allowed for identifier.

        Args:
            identifier: User ID, IP address, etc.

        Returns:
            True if attempt is allowed

        Example:
            >>> if limiter.can_attempt("192.168.1.1"):
            ...     process_request()
        """
        with self._lock:
            now = time.time()

            # Clean old data
            self._cleanup(identifier, now)

            # Check if blocked
            if identifier in self._storage:
                data = self._storage[identifier]
                if data.get("blocked_until", 0) > now:
                    return False

            return True

    def register_failed(self, identifier: str) -> None:
        """
        Register failed attempt for identifier.

        Args:
            identifier: User ID, IP address, etc.

        Side Effects:
            - Increments failure counter
            - May block identifier if max attempts exceeded
        """
        with self._lock:
            now = time.time()
            self._cleanup(identifier, now)

            if identifier not in self._storage:
                self._storage[identifier] = {
                    "attempts": [],
                    "blocked_until": 0,
                    "failures": 0,
                }

            data = self._storage[identifier]
            data["attempts"].append(now)
            data["failures"] = data.get("failures", 0) + 1

            # Check if should block
            if len(data["attempts"]) >= self._max_attempts:
                data["blocked_until"] = now + self._block_duration

    def register_success(self, identifier: str) -> None:
        """
        Register successful attempt - resets counter.

        Args:
            identifier: User ID, IP address, etc.
        """
        with self._lock:
            if identifier in self._storage:
                self._storage[identifier] = {
                    "attempts": [],
                    "blocked_until": 0,
                    "failures": 0,
                }

    def get_delay(self, identifier: str) -> float:
        """
        Get current delay for identifier (exponential backoff).

        Args:
            identifier: User ID, IP address, etc.

        Returns:
            Delay in seconds (0 if no delay)

        Example:
            >>> delay = limiter.get_delay("user123")
            >>> if delay > 0:
            ...     time.sleep(delay)
        """
        with self._lock:
            if identifier not in self._storage:
                return 0.0

            data = self._storage[identifier]
            failures = data.get("failures", 0)

            if failures == 0:
                return 0.0

            # Exponential backoff: base^failures
            delay = self._exponential_base**failures
            return min(delay, self._max_delay)

    def get_remaining_attempts(self, identifier: str) -> int:
        """
        Get remaining attempts before block.

        Args:
            identifier: User ID, IP address, etc.

        Returns:
            Number of remaining attempts
        """
        with self._lock:
            now = time.time()
            self._cleanup(identifier, now)

            if identifier not in self._storage:
                return self._max_attempts

            data = self._storage[identifier]
            attempts_in_window = len(data["attempts"])
            return max(0, self._max_attempts - attempts_in_window)

    def is_blocked(self, identifier: str) -> bool:
        """
        Check if identifier is currently blocked.

        Args:
            identifier: User ID, IP address, etc.

        Returns:
            True if blocked
        """
        with self._lock:
            if identifier not in self._storage:
                return False

            now = time.time()
            return self._storage[identifier].get("blocked_until", 0) > now

    def _cleanup(self, identifier: str, now: float) -> None:
        """Remove old attempts outside window."""
        if identifier not in self._storage:
            return

        data = self._storage[identifier]
        window_start = now - self._window_seconds

        # Filter attempts within window
        data["attempts"] = [t for t in data["attempts"] if t > window_start]

        # Clear block if expired
        if data.get("blocked_until", 0) <= now:
            data["blocked_until"] = 0

    def reset(self, identifier: str) -> None:
        """
        Reset all data for identifier.

        Args:
            identifier: User ID, IP address, etc.
        """
        with self._lock:
            if identifier in self._storage:
                del self._storage[identifier]


# =============================================================================
# Password Strength Checker
# =============================================================================


class PasswordStrengthChecker:
    """
    Password Strength Checker.

    Evaluates password strength using:
    - Length
    - Character variety
    - Entropy calculation
    - Common password detection

    Example:
        >>> checker = PasswordStrengthChecker()
        >>> result = checker.check_strength("MyP@ssw0rd123")
        >>> print(f"Strength: {result.strength}")
        >>> print(f"Entropy: {result.entropy_bits} bits")
    """

    # Character set sizes for entropy calculation
    LOWERCASE = 26
    UPPERCASE = 26
    DIGITS = 10
    SPECIAL = 32

    # Top-100 most common passwords (hardened from 24 to 100)
    COMMON_PASSWORDS = frozenset(
        {
            "password",
            "123456",
            "12345678",
            "qwerty",
            "abc123",
            "monkey",
            "1234567",
            "letmein",
            "trustno1",
            "dragon",
            "baseball",
            "iloveyou",
            "master",
            "sunshine",
            "ashley",
            "bailey",
            "shadow",
            "123123",
            "654321",
            "superman",
            "qazwsx",
            "michael",
            "football",
            "password1",
            "password123",
            "123456789",
            "1234567890",
            "111111",
            "1234",
            "12345",
            "1234567",
            "12345678910",
            "000000",
            "admin",
            "admin123",
            "root",
            "toor",
            "pass",
            "test",
            "guest",
            "master123",
            "changeme",
            "hello",
            "charlie",
            "donald",
            "batman",
            "access",
            "thunder",
            "matrix",
            "love",
            "love123",
            "welcome",
            "welcome1",
            "login",
            "princess",
            "starwars",
            "solo",
            "qwerty123",
            "passw0rd",
            "hello123",
            "fuckme",
            "fuckyou",
            "robert",
            "jordan",
            "jennifer",
            "hunter2",
            "hunter",
            "ranger",
            "buster",
            "soccer",
            "hockey",
            "rachel",
            "secret",
            "summer",
            "spring",
            "winter",
            "george",
            "computer",
            "michelle",
            "jessica",
            "pepper",
            "ginger",
            "flower",
            "carlos",
            "william",
            "samantha",
            "daniel",
            "joshua",
            "andrew",
            "nicholas",
            "anthony",
            "david",
            "alex",
            "chris",
            "taylor",
            "thomas",
            "ranger1",
            "killer",
            "access14",
            "whatever",
            "cookie",
            "richard",
            "maggie",
            "jackson",
            "austin",
        }
    )

    def __init__(
        self,
        min_length: int = 12,
        min_entropy_bits: float = 60.0,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_digits: bool = True,
        require_special: bool = False,
    ):
        """
        Initialize PasswordStrengthChecker.

        Args:
            min_length: Minimum password length
            min_entropy_bits: Minimum required entropy in bits
            require_uppercase: Require uppercase letters
            require_lowercase: Require lowercase letters
            require_digits: Require digits
            require_special: Require special characters
        """
        self._min_length = min_length
        self._min_entropy = min_entropy_bits
        self._require_upper = require_uppercase
        self._require_lower = require_lowercase
        self._require_digits = require_digits
        self._require_special = require_special

    def check_strength(self, password: str) -> PasswordStrengthResult:
        """
        Check password strength.

        Args:
            password: Password to check

        Returns:
            PasswordStrengthResult with assessment

        Example:
            >>> result = checker.check_strength("StrongP@ss123")
            >>> if result.strength >= PasswordStrength.GOOD:
            ...     print("Password is strong enough")
        """
        suggestions: list[str] = []

        # Basic checks
        length = len(password)
        has_lower = bool(re.search(r"[a-z\u0430-\u044f\u0451]", password))
        has_upper = bool(re.search(r"[A-Z\u0410-\u042f\u0401]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(
            re.search(r"[^a-zA-Z\u0430-\u044f\u0410-\u042f\u0451\u04010-9]", password)
        )

        # Check common passwords
        is_common = password.lower() in self.COMMON_PASSWORDS

        # Calculate entropy
        entropy = self._calculate_entropy(password)

        # Estimate crack time
        crack_time = self._estimate_crack_time(entropy)

        # Determine strength
        strength = self._calculate_strength(
            length, entropy, has_lower, has_upper, has_digit, has_special, is_common
        )

        # Generate suggestions
        if length < self._min_length:
            suggestions.append(f"Use at least {self._min_length} characters")
        if not has_lower and self._require_lower:
            suggestions.append("Add lowercase letters")
        if not has_upper and self._require_upper:
            suggestions.append("Add uppercase letters")
        if not has_digit and self._require_digits:
            suggestions.append("Add digits")
        if not has_special and self._require_special:
            suggestions.append("Add special characters")
        if is_common:
            suggestions.append("Avoid common passwords")
        if entropy < self._min_entropy:
            suggestions.append(
                f"Increase entropy (current: {entropy:.1f} bits, need: {self._min_entropy} bits)"
            )

        return PasswordStrengthResult(
            strength=strength,
            entropy_bits=entropy,
            crack_time_estimate=crack_time,
            has_uppercase=has_upper,
            has_lowercase=has_lower,
            has_digits=has_digit,
            has_special=has_special,
            length=length,
            suggestions=suggestions,
        )

    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy in bits using actual character set size.

        Entropy = length * log2(charset_size)

        The charset_size is computed from the actual character classes
        present in the password, giving a precise upper-bound estimate.

        Args:
            password: Password to analyze

        Returns:
            Entropy in bits
        """
        charset_size = 0

        if re.search(r"[a-z\u0430-\u044f\u0451]", password):
            charset_size += self.LOWERCASE
        if re.search(r"[A-Z\u0410-\u042f\u0401]", password):
            charset_size += self.UPPERCASE
        if re.search(r"\d", password):
            charset_size += self.DIGITS
        if re.search(r"[^a-zA-Z\u0430-\u044f\u0410-\u042f\u0451\u04010-9]", password):
            charset_size += self.SPECIAL

        if charset_size == 0:
            return 0.0

        # Entropy = length * log2(charset_size)
        return len(password) * math.log2(charset_size)

    def _estimate_crack_time(self, entropy: float) -> str:
        """
        Estimate time to crack password via brute-force.

        Assumes 10 billion guesses per second (GPU cluster).

        Args:
            entropy: Password entropy in bits

        Returns:
            Human-readable time estimate
        """
        # Guesses per second (high-end GPU cluster)
        guesses_per_second = 10_000_000_000

        # Total combinations = 2^entropy
        combinations = 2**entropy

        # Time in seconds (on average, need to try half)
        seconds = (combinations / 2) / guesses_per_second

        # Convert to human-readable
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.0f} hours"
        elif seconds < 31536000:
            return f"{seconds / 86400:.0f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds / 31536000:.1f} years"
        elif seconds < 31536000 * 1000000:
            return f"{seconds / 31536000:.0f} years"
        elif seconds < 31536000 * 1000000000:
            return f"{seconds / 31536000 / 1000000:.1f} million years"
        else:
            return f"{seconds / 31536000 / 1000000000:.1f} billion years"

    def _calculate_strength(
        self,
        length: int,
        entropy: float,
        has_lower: bool,
        has_upper: bool,
        has_digit: bool,
        has_special: bool,
        is_common: bool,
    ) -> PasswordStrength:
        """
        Calculate overall password strength.

        Returns:
            PasswordStrength enum value
        """
        # Common passwords are always very weak
        if is_common:
            return PasswordStrength.VERY_WEAK

        # Count criteria met
        criteria = sum(
            [
                length >= self._min_length,
                entropy >= self._min_entropy,
                has_lower,
                has_upper,
                has_digit,
                has_special,
            ]
        )

        # Determine strength based on criteria
        if criteria >= 6:
            return PasswordStrength.STRONG
        elif criteria >= 5:
            return PasswordStrength.GOOD
        elif criteria >= 4:
            return PasswordStrength.FAIR
        elif criteria >= 2:
            return PasswordStrength.WEAK
        else:
            return PasswordStrength.VERY_WEAK

    def is_strong_enough(self, password: str) -> Tuple[bool, PasswordStrengthResult]:
        """
        Check if password meets minimum requirements.

        Args:
            password: Password to check

        Returns:
            Tuple of (is_strong_enough, result)

        Example:
            >>> is_valid, result = checker.is_strong_enough("MyP@ss123")
            >>> if not is_valid:
            ...     print(result.suggestions)
        """
        result = self.check_strength(password)
        is_valid = (
            result.length >= self._min_length
            and result.entropy_bits >= self._min_entropy
            and result.strength >= PasswordStrength.GOOD
        )
        return is_valid, result


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Enums
    "PasswordStrength",
    "PasswordStrengthResult",
    # Classes
    "RateLimiter",
    "PasswordStrengthChecker",
]
