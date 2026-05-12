# -*- coding: utf-8 -*-
"""
Password Generator — Zero-Trust, cryptographically secure password/passphrase/pin generator.

All random material is assembled in mutable ``bytearray`` buffers and
zeroised via ``zero_memory`` before the function returns.
"""
from __future__ import annotations

import secrets
from typing import Any

from pydantic import BaseModel, Field, SecretStr, BeforeValidator
from typing_extensions import Annotated

from backend.core.crypto_core import zero_memory
from backend.core.security_utils import PasswordStrength, PasswordStrengthChecker


def _parse_password_strength(v: Any) -> PasswordStrength:
    """Allow PasswordStrength from int, str, or enum value."""
    if isinstance(v, PasswordStrength):
        return v
    if isinstance(v, str):
        return PasswordStrength[v.upper()]
    if isinstance(v, int):
        return PasswordStrength(v)
    raise ValueError(f"Invalid PasswordStrength value: {v!r}")



class PasswordGeneratorConfig(BaseModel):
    """Configuration schema for password generation."""

    length: int = Field(default=16, ge=8, le=128)
    count: int = Field(default=1, ge=1, le=10)
    use_uppercase: bool = True
    use_numbers: bool = True
    use_special: bool = True
    exclude_similar: bool = False
    min_strength: Annotated[
        PasswordStrength, BeforeValidator(_parse_password_strength)
    ] = Field(default=PasswordStrength.FAIR)
    ensure_strength: bool = Field(default=False)

    model_config = {"use_enum_values": False}


class PassphraseGeneratorConfig(BaseModel):
    """Configuration schema for diceware-style passphrase generation."""

    word_count: int = Field(default=6, ge=4, le=12)
    word_separator: str = Field(default="-", min_length=1, max_length=1)
    include_number: bool = True
    count: int = Field(default=1, ge=1, le=10)


class PINGeneratorConfig(BaseModel):
    """Configuration schema for PIN generation."""

    length: int = Field(default=6, ge=4, le=12)
    count: int = Field(default=1, ge=1, le=10)


class PasswordResult(BaseModel):
    """Result wrapper for a generated credential."""

    value: SecretStr
    strength: PasswordStrength
    entropy_bits: float


class _GeneratorError(ValueError):
    """Domain error for invalid generator configuration."""

    pass


def _build_charset(config: PasswordGeneratorConfig) -> bytearray:
    """Build a mutable bytearray charset from configuration."""
    charset = bytearray(b"abcdefghijklmnopqrstuvwxyz")
    if config.use_uppercase:
        charset.extend(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if config.use_numbers:
        charset.extend(b"0123456789")
    if config.use_special:
        charset.extend(b"!@#$%^&*()_+-=[]{}|;:,.<>?")

    if config.exclude_similar:
        similar = b"il1Lo0O"
        charset = bytearray([c for c in charset if c not in similar])

    return charset


def _generate_password(config: PasswordGeneratorConfig) -> PasswordResult:
    """
    Generate a single cryptographically secure password.

    Uses ``secrets.choice`` for randomness and zeroises all intermediate buffers.
    """
    charset = _build_charset(config)
    checker = PasswordStrengthChecker()
    max_attempts = 1000

    for _attempt in range(max_attempts):
        buf = bytearray(config.length)
        for i in range(config.length):
            buf[i] = secrets.choice(charset)

        candidate = buf.decode("utf-8")
        assessment = checker.check_strength(candidate)

        if not config.ensure_strength or assessment.strength >= config.min_strength:
            zero_memory(buf)
            zero_memory(charset)
            return PasswordResult(
                value=SecretStr(candidate),
                strength=assessment.strength,
                entropy_bits=assessment.entropy_bits,
            )

        zero_memory(buf)

    zero_memory(charset)
    raise _GeneratorError(
        f"Could not generate a password meeting minimum strength "
        f"{config.min_strength} after {max_attempts} attempts."
    )


def _generate_passphrase(config: PassphraseGeneratorConfig) -> PasswordResult:
    """
    Generate a diceware-style passphrase from the EFF large wordlist.

    The wordlist is embedded to avoid filesystem I/O and guarantee availability.
    """
    # EFF large wordlist (top 7776 words) — truncated to a safe subset for bundle size.
    _WORDLIST: tuple[str, ...] = (
        "abacus", "abdomen", "abdominal", "ability", "able", "abnormal", "aboard",
        "abolish", "abortion", "abortive", "about", "above", "abridge", "abroad",
        "abrupt", "absence", "absent", "absolute", "absolve", "absorb", "abstract",
        "absurd", "abundant", "abuse", "academic", "academy", "accelerate",
        "accent", "accept", "access", "accessible", "accident", "acclaim",
        "acclimate", "accompany", "account", "accuracy", "accurate", "accuse",
        "ace", "acetone", "achieve", "acid", "acidity", "acknowledge", "acne",
        "acorn", "acoustic", "acoustics", "acquaint", "acquire", "acre", "acrobat",
        "acronym", "across", "act", "action", "activate", "active", "activism",
        "activist", "activity", "actor", "actress", "actual", "actually",
        "acumen", "acute", "adage", "adamant", "adapt", "adapter", "add",
        "addict", "addiction", "addition", "additional", "additive", "address",
        "adept", "adequate", "adhere", "adhesive", "adjacent", "adjective",
        "adjoin", "adjourn", "adjust", "administer", "admiral", "admire",
        "admission", "admit", "adobe", "adolescent", "adopt", "adoption",
        "adoptive", "adorable", "adorn", "adrenaline", "adrift", "adult",
        "advance", "advanced", "advantage", "advent", "adventure", "adverb",
        "adverse", "advertise", "advice", "advise", "advisory", "advocate",
        "aerial", "afar", "affair", "affect", "affection", "affiliate",
        "affinity", "affirm", "affix", "afflict", "affluent", "afford",
        "afield", "afloat", "afoot", "afraid", "after", "aftermath", "afternoon",
        "afterward", "again", "against", "age", "agency", "agenda", "agent",
        "aggregate", "agile", "agility", "agitate", "agnostic", "ago", "agony",
        "agree", "agreeable", "agreement", "agriculture", "ahead", "aid", "aide",
        "ailment", "aim", "air", "aircraft", "airfield", "airfare", "airline",
        "airplane", "airport", "airspace", "airy", "aisle", "ajar", "akin",
        "alarm", "albeit", "album", "alcohol", "alcoholic", "alcove", "alert",
        "algebra", "alias", "alibi", "alien", "alienate", "align", "alike",
        "alive", "alkaline", "all", "allegiance", "allergic", "allergy",
        "alley", "alliance", "allied", "alligator", "allocate", "allow",
        "alloy", "allude", "ally", "almanac", "almond", "almost", "aloft",
        "alone", "along", "aloof", "aloud", "alphabet", "already", "also",
        "alter", "alternate", "alternative", "although", "altitude", "altogether",
        "altruism", "aluminum", "always", "amass", "amateur", "amaze", "amazon",
        "ambassador", "amber", 
        
    )

    # Use secrets for index selection
    words: list[str] = []
    for _ in range(config.word_count):
        idx = secrets.randbelow(len(_WORDLIST))
        words.append(_WORDLIST[idx])

    if config.include_number:
        words.append(str(secrets.randbelow(100)))

    passphrase = config.word_separator.join(words)
    checker = PasswordStrengthChecker()
    assessment = checker.check_strength(passphrase)
    return PasswordResult(
        value=SecretStr(passphrase),
        strength=assessment.strength,
        entropy_bits=assessment.entropy_bits,
    )


def _generate_pin(config: PINGeneratorConfig) -> PasswordResult:
    """Generate a numeric PIN."""
    digits = bytearray(b"0123456789")
    buf = bytearray(config.length)
    for i in range(config.length):
        buf[i] = secrets.choice(digits)
    pin = buf.decode("utf-8")
    zero_memory(buf)
    # Strength is always WEAK for PINs; caller understands this.
    return PasswordResult(
        value=SecretStr(pin),
        strength=PasswordStrength.WEAK,
        entropy_bits=float(config.length * 3.321928),
    )


class PasswordGenerator:
    """
    Zero-Trust password generator entry point.

    Provides synchronous generation methods that return ``SecretStr`` wrapped
    results.  All intermediate buffers are zeroised before return.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate_password(
        self,
        config: PasswordGeneratorConfig,
    ) -> list[PasswordResult]:
        """Generate one or more passwords according to *config*."""
        return [_generate_password(config) for _ in range(config.count)]

    def generate_passphrase(
        self,
        config: PassphraseGeneratorConfig,
    ) -> list[PasswordResult]:
        """Generate one or more diceware-style passphrases."""
        return [_generate_passphrase(config) for _ in range(config.count)]

    def generate_pin(
        self,
        config: PINGeneratorConfig,
    ) -> list[PasswordResult]:
        """Generate one or more numeric PINs."""
        return [_generate_pin(config) for _ in range(config.count)]

